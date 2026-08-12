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
  | CMOVNBE = 77
  /// Conditional Move.
  | CMOVNB = 78
  | CMOVAE = 78
  | CMOVNC = 78
  /// Conditional Move.
  | CMOVB = 79
  | CMOVC = 79
  | CMOVNAE = 79
  /// Conditional Move.
  | CMOVBE = 80
  | CMOVNA = 80
  /// Conditional Move.
  | CMOVZ = 81
  | CMOVE = 81
  /// Conditional Move.
  | CMOVG = 82
  | CMOVNLE = 82
  /// Conditional Move.
  | CMOVNL = 83
  | CMOVGE = 83
  /// Conditional Move.
  | CMOVL = 84
  | CMOVNGE = 84
  /// Conditional Move.
  | CMOVLE = 85
  | CMOVNG = 85
  /// Conditional Move.
  | CMOVNZ = 86
  | CMOVNE = 86
  /// Conditional Move.
  | CMOVNO = 87
  /// Conditional Move.
  | CMOVNP = 88
  | CMOVPO = 88
  /// Conditional Move.
  | CMOVNS = 89
  /// Conditional Move.
  | CMOVO = 90
  /// Conditional Move.
  | CMOVP = 91
  | CMOVPE = 91
  /// Conditional Move.
  | CMOVS = 92
  /// Compare Two Operands.
  | CMP = 93
  /// Compare and Add if Condition is Met.
  | CMPBEXADD = 94
  /// Compare and Add if Condition is Met.
  | CMPBXADD = 95
  /// Compare and Add if Condition is Met.
  | CMPLEXADD = 96
  /// Compare and Add if Condition is Met.
  | CMPLXADD = 97
  /// Compare and Add if Condition is Met.
  | CMPNBEXADD = 98
  /// Compare and Add if Condition is Met.
  | CMPNBXADD = 99
  /// Compare and Add if Condition is Met.
  | CMPNLEXADD = 100
  /// Compare and Add if Condition is Met.
  | CMPNLXADD = 101
  /// Compare and Add if Condition is Met.
  | CMPNOXADD = 102
  /// Compare and Add if Condition is Met.
  | CMPNPXADD = 103
  /// Compare and Add if Condition is Met.
  | CMPNSXADD = 104
  /// Compare and Add if Condition is Met.
  | CMPNZXADD = 105
  /// Compare and Add if Condition is Met.
  | CMPOXADD = 106
  /// Compare Packed Double Precision Floating-Point Values.
  | CMPPD = 107
  /// Compare Packed Single Precision Floating-Point Values.
  | CMPPS = 108
  /// Compare and Add if Condition is Met.
  | CMPPXADD = 109
  /// Compare String Operands.
  | CMPS = 110
  /// Compare String Operands.
  | CMPSB = 111
  /// Compare String Operands.
  /// Compare Scalar Double Precision Floating-Point Value.
  | CMPSD = 112
  /// Compare String Operands.
  | CMPSQ = 113
  /// Compare Scalar Single Precision Floating-Point Value.
  | CMPSS = 114
  /// Compare String Operands.
  | CMPSW = 115
  /// Compare and Add if Condition is Met.
  | CMPSXADD = 116
  /// Compare and Exchange.
  | CMPXCHG = 117
  /// Compare and Exchange Bytes.
  | CMPXCHG16B = 118
  /// Compare and Exchange Bytes.
  | CMPXCHG8B = 119
  /// Compare and Add if Condition is Met.
  | CMPZXADD = 120
  /// Compare Scalar Ordered Double Precision Floating-Point Values and Set
  /// EFLAGS.
  | COMISD = 121
  /// Compare Scalar Ordered Single Precision Floating-Point Values and Set
  /// EFLAGS.
  | COMISS = 122
  /// CPU Identification.
  | CPUID = 123
  /// Convert Word to Doubleword/Convert Doubleword to Quadword.
  | CQO = 124
  /// Accumulate CRC32 Value.
  | CRC32 = 125
  /// Convert Packed Doubleword Integers to Packed Double Precision
  /// Floating-Point Values.
  | CVTDQ2PD = 126
  /// Convert Packed Doubleword Integers to Packed Single Precision
  /// Floating-Point Values.
  | CVTDQ2PS = 127
  /// Convert Packed Double Precision Floating-Point Values to Packed Doubleword
  /// Integers.
  | CVTPD2DQ = 128
  /// Convert Packed Double Precision Floating-Point Values to Packed Dword
  /// Integers.
  | CVTPD2PI = 129
  /// Convert Packed Double Precision Floating-Point Values to Packed Single
  /// Precision Floating-Point Values.
  | CVTPD2PS = 130
  /// Convert Packed Dword Integers to Packed Double Precision Floating-Point
  /// Values.
  | CVTPI2PD = 131
  /// Convert Packed Dword Integers to Packed Single Precision Floating-Point
  /// Values.
  | CVTPI2PS = 132
  /// Convert Packed Single Precision Floating-Point Values to Packed Signed
  /// Doubleword Integer Values.
  | CVTPS2DQ = 133
  /// Convert Packed Single Precision Floating-Point Values to Packed Double
  /// Precision Floating-Point Values.
  | CVTPS2PD = 134
  /// Convert Packed Single Precision Floating-Point Values to Packed Dword
  /// Integers.
  | CVTPS2PI = 135
  /// Convert Scalar Double Precision Floating-Point Value to Signed Integer.
  | CVTSD2SI = 136
  /// Convert Scalar Double Precision Floating-Point Value to Scalar Single
  /// Precision Floating-Point Value.
  | CVTSD2SS = 137
  /// Convert Signed Integer to Scalar Double Precision Floating-Point Value.
  | CVTSI2SD = 138
  /// Convert Signed Integer to Scalar Single Precision Floating-Point Value.
  | CVTSI2SS = 139
  /// Convert Scalar Single Precision Floating-Point Value to Scalar Double
  /// Precision Floating-Point Value.
  | CVTSS2SD = 140
  /// Convert Scalar Single Precision Floating-Point Value to Signed Integer.
  | CVTSS2SI = 141
  /// Convert with Truncation Packed Double Precision Floating-Point Values to
  /// Packed Doubleword Integers.
  | CVTTPD2DQ = 142
  /// Convert With Truncation Packed Double Precision Floating-Point Values to
  /// Packed Dword Integers.
  | CVTTPD2PI = 143
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Signed Doubleword Integer Values.
  | CVTTPS2DQ = 144
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Dword Integers.
  | CVTTPS2PI = 145
  /// Convert With Truncation Scalar Double Precision Floating-Point Value to
  /// Signed Integer.
  | CVTTSD2SI = 146
  /// Convert With Truncation Scalar Single Precision Floating-Point Value to
  /// Signed Integer.
  | CVTTSS2SI = 147
  /// Convert Word to Doubleword/Convert Doubleword to Quadword.
  | CWD = 148
  /// Convert Byte to Word/Convert Word to Doubleword/Convert Doubleword to
  /// Quadword.
  | CWDE = 149
  /// Decimal Adjust AL After Addition.
  | DAA = 150
  /// Decimal Adjust AL After Subtraction.
  | DAS = 151
  /// Decrement by 1.
  | DEC = 152
  /// Unsigned Divide.
  | DIV = 153
  /// Divide Packed Double Precision Floating-Point Values.
  | DIVPD = 154
  /// Divide Packed Single Precision Floating-Point Values.
  | DIVPS = 155
  /// Divide Scalar Double Precision Floating-Point Value.
  | DIVSD = 156
  /// Divide Scalar Single Precision Floating-Point Values.
  | DIVSS = 157
  /// Dot Product of Packed Double Precision Floating-Point Values.
  | DPPD = 158
  /// Dot Product of Packed Single Precision Floating-Point Values.
  | DPPS = 159
  /// Empty MMX Technology State.
  | EMMS = 160
  /// Encode 128-Bit Key With Key Locker.
  | ENCODEKEY128 = 161
  /// Encode 256-Bit Key With Key Locker.
  | ENCODEKEY256 = 162
  /// Terminate an Indirect Branch in 32-bit and Compatibility Mode.
  | ENDBR32 = 163
  /// Terminate an Indirect Branch in 64-bit Mode.
  | ENDBR64 = 164
  /// Enqueue Command.
  | ENQCMD = 165
  /// Enqueue Command Supervisor.
  | ENQCMDS = 166
  /// Make Stack Frame for Procedure Parameters.
  | ENTER = 167
  /// Extract Packed Floating-Point Values.
  | EXTRACTPS = 168
  /// Extract Field from Register.
  | EXTRQ = 169
  /// Compute 2x-1.
  | F2XM1 = 170
  /// Absolute Value.
  | FABS = 171
  /// Add.
  | FADD = 172
  /// Add.
  | FADDP = 173
  /// Load Binary Coded Decimal.
  | FBLD = 174
  /// Store BCD Integer and Pop.
  | FBSTP = 175
  /// Change Sign.
  | FCHS = 176
  /// Clear Exceptions.
  | FCLEX = 177
  /// Floating-Point Conditional Move.
  | FCMOVB = 178
  /// Floating-Point Conditional Move.
  | FCMOVBE = 179
  /// Floating-Point Conditional Move.
  | FCMOVE = 180
  /// Floating-Point Conditional Move.
  | FCMOVNB = 181
  /// Floating-Point Conditional Move.
  | FCMOVNBE = 182
  /// Floating-Point Conditional Move.
  | FCMOVNE = 183
  /// Floating-Point Conditional Move.
  | FCMOVNU = 184
  /// Floating-Point Conditional Move.
  | FCMOVU = 185
  /// Compare Floating-Point Values.
  | FCOM = 186
  /// Compare Floating-Point Values and Set EFLAGS.
  | FCOMI = 187
  /// Compare Floating-Point Values and Set EFLAGS.
  | FCOMIP = 188
  /// Compare Floating-Point Values.
  | FCOMP = 189
  /// Compare Floating-Point Values.
  | FCOMPP = 190
  /// Cosine.
  | FCOS = 191
  /// Decrement Stack-Top Pointer.
  | FDECSTP = 192
  /// Divide.
  | FDIV = 193
  /// Divide.
  | FDIVP = 194
  /// Reverse Divide.
  | FDIVR = 195
  /// Reverse Divide.
  | FDIVRP = 196
  /// Free Floating-Point Register.
  | FFREE = 197
  /// Performs FFREE ST(i) and pop stack.
  | FFREEP = 198
  /// Add.
  | FIADD = 199
  /// Compare Integer.
  | FICOM = 200
  /// Compare Integer.
  | FICOMP = 201
  /// Divide.
  | FIDIV = 202
  /// Reverse Divide.
  | FIDIVR = 203
  /// Load Integer.
  | FILD = 204
  /// Multiply.
  | FIMUL = 205
  /// Increment Stack-Top Pointer.
  | FINCSTP = 206
  /// Initialize Floating-Point Unit.
  | FINIT = 207
  /// Store Integer.
  | FIST = 208
  /// Store Integer.
  | FISTP = 209
  /// Store Integer With Truncation.
  | FISTTP = 210
  /// Subtract.
  | FISUB = 211
  /// Reverse Subtract.
  | FISUBR = 212
  /// Load Floating-Point Value.
  | FLD = 213
  /// Load Constant.
  | FLD1 = 214
  /// Load x87 FPU Control Word.
  | FLDCW = 215
  /// Load x87 FPU Environment.
  | FLDENV = 216
  /// Load Constant.
  | FLDL2E = 217
  /// Load Constant.
  | FLDL2T = 218
  /// Load Constant.
  | FLDLG2 = 219
  /// Load Constant.
  | FLDLN2 = 220
  /// Load Constant.
  | FLDPI = 221
  /// Load Constant.
  | FLDZ = 222
  /// Multiply.
  | FMUL = 223
  /// Multiply.
  | FMULP = 224
  /// Clear Exceptions.
  | FNCLEX = 225
  /// Initialize Floating-Point Unit.
  | FNINIT = 226
  /// No Operation.
  | FNOP = 227
  /// Store x87 FPU State.
  | FNSAVE = 228
  /// Store x87 FPU Control Word.
  | FNSTCW = 229
  /// Store x87 FPU Environment.
  | FNSTENV = 230
  /// Store x87 FPU Status Word.
  | FNSTSW = 231
  /// Partial Arctangent.
  | FPATAN = 232
  /// Partial Remainder.
  | FPREM = 233
  /// Partial Remainder.
  | FPREM1 = 234
  /// Partial Tangent.
  | FPTAN = 235
  /// Round to Integer.
  | FRNDINT = 236
  /// Restore x87 FPU State.
  | FRSTOR = 237
  /// Store x87 FPU State.
  | FSAVE = 238
  /// Scale.
  | FSCALE = 239
  /// Sine.
  | FSIN = 240
  /// Sine and Cosine.
  | FSINCOS = 241
  /// Square Root.
  | FSQRT = 242
  /// Store Floating-Point Value.
  | FST = 243
  /// Store x87 FPU Control Word.
  | FSTCW = 244
  /// Store x87 FPU Environment.
  | FSTENV = 245
  /// Store Floating-Point Value.
  | FSTP = 246
  /// Store x87 FPU Status Word.
  | FSTSW = 247
  /// Subtract.
  | FSUB = 248
  /// Subtract.
  | FSUBP = 249
  /// Reverse Subtract.
  | FSUBR = 250
  /// Reverse Subtract.
  | FSUBRP = 251
  /// TEST.
  | FTST = 252
  /// Unordered Compare Floating-Point Values.
  | FUCOM = 253
  /// Compare Floating-Point Values and Set EFLAGS.
  | FUCOMI = 254
  /// Compare Floating-Point Values and Set EFLAGS.
  | FUCOMIP = 255
  /// Unordered Compare Floating-Point Values.
  | FUCOMP = 256
  /// Unordered Compare Floating-Point Values.
  | FUCOMPP = 257
  /// Wait.
  | FWAIT = 258
  /// Examine Floating-Point.
  | FXAM = 259
  /// Exchange Register Contents.
  | FXCH = 260
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR = 261
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR64 = 262
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE = 263
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE64 = 264
  /// Extract Exponent and Significand.
  | FXTRACT = 265
  /// Compute y * log2x.
  | FYL2X = 266
  /// Compute y * log2(x +1).
  | FYL2XP1 = 267
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
  | GETSEC = 268
  /// Galois Field Affine Transformation Inverse.
  | GF2P8AFFINEINVQB = 269
  /// Galois Field Affine Transformation.
  | GF2P8AFFINEQB = 270
  /// Galois Field Multiply Bytes.
  | GF2P8MULB = 271
  /// Packed Double Precision Floating-Point Horizontal Add.
  | HADDPD = 272
  /// Packed Single Precision Floating-Point Horizontal Add.
  | HADDPS = 273
  /// Halt.
  | HLT = 274
  /// History Reset.
  | HRESET = 275
  /// Packed Double Precision Floating-Point Horizontal Subtract.
  | HSUBPD = 276
  /// Packed Single Precision Floating-Point Horizontal Subtract.
  | HSUBPS = 277
  /// Signed Divide.
  | IDIV = 278
  /// Signed Multiply.
  | IMUL = 279
  /// Input From Port.
  | IN = 280
  /// Increment by 1.
  | INC = 281
  /// Increment Shadow Stack Pointer.
  | INCSSPD = 282
  /// Increment Shadow Stack Pointer.
  | INCSSPQ = 283
  /// Input from Port to String.
  | INS = 284
  /// Input from Port to String.
  | INSB = 285
  /// Input from Port to String.
  | INSD = 286
  /// Insert Scalar Single Precision Floating-Point Value.
  | INSERTPS = 287
  /// Inserts Field from a source Register to a destination Register.
  | INSERTQ = 288
  /// Input from Port to String.
  | INSW = 289
  /// Call to Interrupt Procedure.
  | INT = 290
  /// Call to Interrupt Procedure.
  | INT1 = 291
  /// Call to Interrupt Procedure.
  | INT3 = 292
  /// Call to Interrupt Procedure.
  | INTO = 293
  /// Invalidate Internal Caches.
  | INVD = 294
  /// Invalidate TLB Entries.
  | INVLPG = 295
  /// Invalidate Process-Context Identifier.
  | INVPCID = 296
  /// Interrupt Return.
  | IRET = 297
  /// Interrupt Return.
  | IRETD = 298
  /// Interrupt Return.
  | IRETQ = 299
  /// Interrupt return (16-bit operand size).
  | IRETW = 300
  /// Jump if Condition Is Met.
  | JA = 301
  | JNBE = 301
  /// Jump if Condition Is Met.
  | JNB = 302
  | JAE = 302
  | JNC = 302
  /// Jump if Condition Is Met.
  | JB = 303
  | JC = 303
  | JNAE = 303
  /// Jump if Condition Is Met.
  | JBE = 304
  | JNA = 304
  /// Jump if Condition Is Met.
  | JCXZ = 305
  /// Jump if Condition Is Met.
  | JZ = 306
  | JE = 306
  /// Jump if Condition Is Met.
  | JECXZ = 307
  /// Jump if Condition Is Met.
  | JG = 308
  | JNLE = 308
  /// Jump if Condition Is Met.
  | JNL = 309
  | JGE = 309
  /// Jump if Condition Is Met.
  | JL = 310
  | JNGE = 310
  /// Jump if Condition Is Met.
  | JLE = 311
  | JNG = 311
  /// Jump.
  | JMP = 312
  /// Jump if Condition Is Met.
  | JNZ = 313
  | JNE = 313
  /// Jump if Condition Is Met.
  | JNO = 314
  /// Jump if Condition Is Met.
  | JNP = 315
  | JPO = 315
  /// Jump if Condition Is Met.
  | JNS = 316
  /// Jump if Condition Is Met.
  | JO = 317
  /// Jump if Condition Is Met.
  | JP = 318
  | JPE = 318
  /// Jump if Condition Is Met.
  | JRCXZ = 319
  /// Jump if Condition Is Met.
  | JS = 320
  /// ADD Two Masks.
  | KADDB = 321
  /// ADD Two Masks.
  | KADDD = 322
  /// ADD Two Masks.
  | KADDQ = 323
  /// ADD Two Masks.
  | KADDW = 324
  /// Bitwise Logical AND Masks.
  | KANDB = 325
  /// Bitwise Logical AND Masks.
  | KANDD = 326
  /// Bitwise Logical AND NOT Masks.
  | KANDNB = 327
  /// Bitwise Logical AND NOT Masks.
  | KANDND = 328
  /// Bitwise Logical AND NOT Masks.
  | KANDNQ = 329
  /// Bitwise Logical AND NOT Masks.
  | KANDNW = 330
  /// Bitwise Logical AND Masks.
  | KANDQ = 331
  /// Bitwise Logical AND Masks.
  | KANDW = 332
  /// Move From and to Mask Registers.
  | KMOVB = 333
  /// Move From and to Mask Registers.
  | KMOVD = 334
  /// Move From and to Mask Registers.
  | KMOVQ = 335
  /// Move From and to Mask Registers.
  | KMOVW = 336
  /// NOT Mask Register.
  | KNOTB = 337
  /// NOT Mask Register.
  | KNOTD = 338
  /// NOT Mask Register.
  | KNOTQ = 339
  /// NOT Mask Register.
  | KNOTW = 340
  /// Bitwise Logical OR Masks.
  | KORB = 341
  /// Bitwise Logical OR Masks.
  | KORD = 342
  /// Bitwise Logical OR Masks.
  | KORQ = 343
  /// OR Masks and Set Flags.
  | KORTESTB = 344
  /// OR Masks and Set Flags.
  | KORTESTD = 345
  /// OR Masks and Set Flags.
  | KORTESTQ = 346
  /// OR Masks and Set Flags.
  | KORTESTW = 347
  /// Bitwise Logical OR Masks.
  | KORW = 348
  /// Shift Left Mask Registers.
  | KSHIFTLB = 349
  /// Shift Left Mask Registers.
  | KSHIFTLD = 350
  /// Shift Left Mask Registers.
  | KSHIFTLQ = 351
  /// Shift Left Mask Registers.
  | KSHIFTLW = 352
  /// Shift Right Mask Registers.
  | KSHIFTRB = 353
  /// Shift Right Mask Registers.
  | KSHIFTRD = 354
  /// Shift Right Mask Registers.
  | KSHIFTRQ = 355
  /// Shift Right Mask Registers.
  | KSHIFTRW = 356
  /// Packed Bit Test Masks and Set Flags.
  | KTESTB = 357
  /// Packed Bit Test Masks and Set Flags.
  | KTESTD = 358
  /// Packed Bit Test Masks and Set Flags.
  | KTESTQ = 359
  /// Packed Bit Test Masks and Set Flags.
  | KTESTW = 360
  /// Unpack for Mask Registers.
  | KUNPCKBW = 361
  /// Unpack for Mask Registers.
  | KUNPCKDQ = 362
  /// Unpack for Mask Registers.
  | KUNPCKWD = 363
  /// Bitwise Logical XNOR Masks.
  | KXNORB = 364
  /// Bitwise Logical XNOR Masks.
  | KXNORD = 365
  /// Bitwise Logical XNOR Masks.
  | KXNORQ = 366
  /// Bitwise Logical XNOR Masks.
  | KXNORW = 367
  /// Bitwise Logical XOR Masks.
  | KXORB = 368
  /// Bitwise Logical XOR Masks.
  | KXORD = 369
  /// Bitwise Logical XOR Masks.
  | KXORQ = 370
  /// Bitwise Logical XOR Masks.
  | KXORW = 371
  /// Load Status Flags Into AH Register.
  | LAHF = 372
  /// Load Access Rights.
  | LAR = 373
  /// Load Unaligned Integer 128 Bits.
  | LDDQU = 374
  /// Load MXCSR Register.
  | LDMXCSR = 375
  /// Load Far Pointer.
  | LDS = 376
  /// Load Tile Configuration.
  | LDTILECFG = 377
  /// Load Effective Address.
  | LEA = 378
  /// High Level Procedure Exit.
  | LEAVE = 379
  /// Load Far Pointer.
  | LES = 380
  /// Load Fence.
  | LFENCE = 381
  /// Load Far Pointer.
  | LFS = 382
  /// Load Global/Interrupt Descriptor Table Register.
  | LGDT = 383
  /// Load Far Pointer.
  | LGS = 384
  /// Load Global/Interrupt Descriptor Table Register.
  | LIDT = 385
  /// Load Local Descriptor Table Register.
  | LLDT = 386
  /// Load Machine Status Word.
  | LMSW = 387
  /// Load Internal Wrapping Key With Key Locker.
  | LOADIWKEY = 388
  /// Assert LOCK# Signal Prefix.
  | LOCK = 389
  /// Load String.
  | LODS = 390
  /// Load String.
  | LODSB = 391
  /// Load String.
  | LODSD = 392
  /// Load String.
  | LODSQ = 393
  /// Load String.
  | LODSW = 394
  /// Loop According to ECX Counter.
  | LOOP = 395
  /// Loop According to ECX Counter.
  | LOOPE = 396
  /// Loop According to ECX Counter.
  | LOOPNE = 397
  /// Load Segment Limit.
  | LSL = 398
  /// Load Far Pointer.
  | LSS = 399
  /// Load Task Register.
  | LTR = 400
  /// Count the Number of Leading Zero Bits.
  | LZCNT = 401
  /// Store Selected Bytes of Double Quadword.
  | MASKMOVDQU = 402
  /// Store Selected Bytes of Quadword.
  | MASKMOVQ = 403
  /// Maximum of Packed Double Precision Floating-Point Values.
  | MAXPD = 404
  /// Maximum of Packed Single Precision Floating-Point Values.
  | MAXPS = 405
  /// Return Maximum Scalar Double Precision Floating-Point Value.
  | MAXSD = 406
  /// Return Maximum Scalar Single Precision Floating-Point Value.
  | MAXSS = 407
  /// Memory Fence.
  | MFENCE = 408
  /// Minimum of Packed Double Precision Floating-Point Values.
  | MINPD = 409
  /// Minimum of Packed Single Precision Floating-Point Values.
  | MINPS = 410
  /// Return Minimum Scalar Double Precision Floating-Point Value.
  | MINSD = 411
  /// Return Minimum Scalar Single Precision Floating-Point Value.
  | MINSS = 412
  /// Set Up Monitor Address.
  | MONITOR = 413
  /// Montgomery multiplier (PMM).
  | MONTMUL = 414
  /// Montgomery multiplier (PMM).
  | MONTMUL2 = 415
  /// Move.
  | MOV = 416
  /// Move Aligned Packed Double Precision Floating-Point Values.
  | MOVAPD = 417
  /// Move Aligned Packed Single Precision Floating-Point Values.
  | MOVAPS = 418
  /// Move Data After Swapping Bytes.
  | MOVBE = 419
  /// Move Doubleword/Move Quadword.
  | MOVD = 420
  /// Replicate Double Precision Floating-Point Values.
  | MOVDDUP = 421
  /// Move 64 Bytes as Direct Store.
  | MOVDIR64B = 422
  /// Move Doubleword as Direct Store.
  | MOVDIRI = 423
  /// Move Quadword from XMM to MMX Technology Register.
  | MOVDQ2Q = 424
  /// Move Aligned Packed Integer Values.
  | MOVDQA = 425
  /// Move Unaligned Packed Integer Values.
  | MOVDQU = 426
  /// Move Packed Single Precision Floating-Point Values High to Low.
  | MOVHLPS = 427
  /// Move High Packed Double Precision Floating-Point Value.
  | MOVHPD = 428
  /// Move High Packed Single Precision Floating-Point Values.
  | MOVHPS = 429
  /// Move Packed Single Precision Floating-Point Values Low to High.
  | MOVLHPS = 430
  /// Move Low Packed Double Precision Floating-Point Value.
  | MOVLPD = 431
  /// Move Low Packed Single Precision Floating-Point Values.
  | MOVLPS = 432
  /// Extract Packed Double Precision Floating-Point Sign Mask.
  | MOVMSKPD = 433
  /// Extract Packed Single Precision Floating-Point Sign Mask.
  | MOVMSKPS = 434
  /// Store Packed Integers Using Non-Temporal Hint.
  | MOVNTDQ = 435
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQA = 436
  /// Store Doubleword Using Non-Temporal Hint.
  | MOVNTI = 437
  /// Store Packed Double Precision Floating-Point Values Using Non-Temporal
  /// Hint.
  | MOVNTPD = 438
  /// Store Packed Single Precision Floating-Point Values Using Non-Temporal
  /// Hint.
  | MOVNTPS = 439
  /// Store of Quadword Using Non-Temporal Hint.
  | MOVNTQ = 440
  /// Move Doubleword/Move Quadword.
  /// Move Quadword.
  | MOVQ = 441
  /// Move Quadword from MMX Technology to XMM Register.
  | MOVQ2DQ = 442
  /// Move Data From String to String.
  | MOVS = 443
  /// Move Data From String to String.
  | MOVSB = 444
  /// Move Data From String to String.
  /// Move or Merge Scalar Double Precision Floating-Point Value.
  | MOVSD = 445
  /// Replicate Single Precision Floating-Point Values.
  | MOVSHDUP = 446
  /// Replicate Single Precision Floating-Point Values.
  | MOVSLDUP = 447
  /// Move Data From String to String.
  | MOVSQ = 448
  /// Move or Merge Scalar Single Precision Floating-Point Value.
  | MOVSS = 449
  /// Move Data From String to String.
  | MOVSW = 450
  /// Move With Sign-Extension.
  | MOVSX = 451
  /// Move With Sign-Extension.
  | MOVSXD = 452
  /// Move Unaligned Packed Double Precision Floating-Point Values.
  | MOVUPD = 453
  /// Move Unaligned Packed Single Precision Floating-Point Values.
  | MOVUPS = 454
  /// Move With Zero-Extend.
  | MOVZX = 455
  /// Compute Multiple Packed Sums of Absolute Difference.
  | MPSADBW = 456
  /// Unsigned Multiply.
  | MUL = 457
  /// Multiply Packed Double Precision Floating-Point Values.
  | MULPD = 458
  /// Multiply Packed Single Precision Floating-Point Values.
  | MULPS = 459
  /// Multiply Scalar Double Precision Floating-Point Value.
  | MULSD = 460
  /// Multiply Scalar Single Precision Floating-Point Values.
  | MULSS = 461
  /// Unsigned Multiply Without Affecting Flags.
  | MULX = 462
  /// Monitor Wait.
  | MWAIT = 463
  /// Two's Complement Negation.
  | NEG = 464
  /// No Operation.
  | NOP = 465
  /// One's Complement Negation.
  | NOT = 466
  /// Logical Inclusive OR.
  | OR = 467
  /// Bitwise Logical OR of Packed Double Precision Floating-Point Values.
  | ORPD = 468
  /// Bitwise Logical OR of Packed Single Precision Floating-Point Values.
  | ORPS = 469
  /// Output to Port.
  | OUT = 470
  /// Output String to Port.
  | OUTS = 471
  /// Output String to Port.
  | OUTSB = 472
  /// Output String to Port.
  | OUTSD = 473
  /// Output String to Port.
  | OUTSW = 474
  /// Packed Absolute Value.
  | PABSB = 475
  /// Packed Absolute Value.
  | PABSD = 476
  /// Packed Absolute Value.
  | PABSW = 477
  /// Pack With Signed Saturation.
  | PACKSSDW = 478
  /// Pack With Signed Saturation.
  | PACKSSWB = 479
  /// Pack With Unsigned Saturation.
  | PACKUSDW = 480
  /// Pack With Unsigned Saturation.
  | PACKUSWB = 481
  /// Add Packed Integers.
  | PADDB = 482
  /// Add Packed Integers.
  | PADDD = 483
  /// Add Packed Integers.
  | PADDQ = 484
  /// Add Packed Signed Integers with Signed Saturation.
  | PADDSB = 485
  /// Add Packed Signed Integers with Signed Saturation.
  | PADDSW = 486
  /// Add Packed Unsigned Integers With Unsigned Saturation.
  | PADDUSB = 487
  /// Add Packed Unsigned Integers With Unsigned Saturation.
  | PADDUSW = 488
  /// Add Packed Integers.
  | PADDW = 489
  /// Packed Align Right.
  | PALIGNR = 490
  /// Logical AND.
  | PAND = 491
  /// Logical AND NOT.
  | PANDN = 492
  /// Spin Loop Hint.
  | PAUSE = 493
  /// Average Packed Integers.
  | PAVGB = 494
  /// Average Packed Integers.
  | PAVGW = 495
  /// Variable Blend Packed Bytes.
  | PBLENDVB = 496
  /// Blend Packed Words.
  | PBLENDW = 497
  /// Carry-Less Multiplication Quadword.
  | PCLMULQDQ = 498
  /// Compare Packed Data for Equal.
  | PCMPEQB = 499
  /// Compare Packed Data for Equal.
  | PCMPEQD = 500
  /// Compare Packed Qword Data for Equal.
  | PCMPEQQ = 501
  /// Compare Packed Data for Equal.
  | PCMPEQW = 502
  /// Packed Compare Explicit Length Strings, Return Index.
  | PCMPESTRI = 503
  /// Packed Compare Explicit Length Strings, Return Mask.
  | PCMPESTRM = 504
  /// Compare Packed Signed Integers for Greater Than.
  | PCMPGTB = 505
  /// Compare Packed Signed Integers for Greater Than.
  | PCMPGTD = 506
  /// Compare Packed Data for Greater Than.
  | PCMPGTQ = 507
  /// Compare Packed Signed Integers for Greater Than.
  | PCMPGTW = 508
  /// Packed Compare Implicit Length Strings, Return Index.
  | PCMPISTRI = 509
  /// Packed Compare Implicit Length Strings, Return Mask.
  | PCMPISTRM = 510
  /// Platform Configuration.
  | PCONFIG = 511
  /// Parallel Bits Deposit.
  | PDEP = 512
  /// Parallel Bits Extract.
  | PEXT = 513
  /// Extract Byte/Dword/Qword.
  | PEXTRB = 514
  /// Extract Byte/Dword/Qword.
  | PEXTRD = 515
  /// Extract Byte/Dword/Qword.
  | PEXTRQ = 516
  /// Extract Word.
  | PEXTRW = 517
  /// Packed Horizontal Add.
  | PHADDD = 518
  /// Packed Horizontal Add and Saturate.
  | PHADDSW = 519
  /// Packed Horizontal Add.
  | PHADDW = 520
  /// Packed Horizontal Word Minimum.
  | PHMINPOSUW = 521
  /// Packed Horizontal Subtract.
  | PHSUBD = 522
  /// Packed Horizontal Subtract and Saturate.
  | PHSUBSW = 523
  /// Packed Horizontal Subtract.
  | PHSUBW = 524
  /// Insert Byte/Dword/Qword.
  | PINSRB = 525
  /// Insert Byte/Dword/Qword.
  | PINSRD = 526
  /// Insert Byte/Dword/Qword.
  | PINSRQ = 527
  /// Insert Word.
  | PINSRW = 528
  /// Multiply and Add Packed Signed and Unsigned Bytes.
  | PMADDUBSW = 529
  /// Multiply and Add Packed Integers.
  | PMADDWD = 530
  /// Maximum of Packed Signed Integers.
  | PMAXSB = 531
  /// Maximum of Packed Signed Integers.
  | PMAXSD = 532
  /// Maximum of Packed Signed Integers.
  | PMAXSW = 533
  /// Maximum of Packed Unsigned Integers.
  | PMAXUB = 534
  /// Maximum of Packed Unsigned Integers.
  | PMAXUD = 535
  /// Maximum of Packed Unsigned Integers.
  | PMAXUW = 536
  /// Minimum of Packed Signed Integers.
  | PMINSB = 537
  /// Minimum of Packed Signed Integers.
  | PMINSD = 538
  /// Minimum of Packed Signed Integers.
  | PMINSW = 539
  /// Minimum of Packed Unsigned Integers.
  | PMINUB = 540
  /// Minimum of Packed Unsigned Integers.
  | PMINUD = 541
  /// Minimum of Packed Unsigned Integers.
  | PMINUW = 542
  /// Move Byte Mask.
  | PMOVMSKB = 543
  /// Packed Move With Sign Extend.
  | PMOVSXBD = 544
  /// Packed Move With Sign Extend.
  | PMOVSXBQ = 545
  /// Packed Move With Sign Extend.
  | PMOVSXBW = 546
  /// Packed Move With Sign Extend.
  | PMOVSXDQ = 547
  /// Packed Move With Sign Extend.
  | PMOVSXWD = 548
  /// Packed Move With Sign Extend.
  | PMOVSXWQ = 549
  /// Packed Move With Zero Extend.
  | PMOVZXBD = 550
  /// Packed Move With Zero Extend.
  | PMOVZXBQ = 551
  /// Packed Move With Zero Extend.
  | PMOVZXBW = 552
  /// Packed Move With Zero Extend.
  | PMOVZXDQ = 553
  /// Packed Move With Zero Extend.
  | PMOVZXWD = 554
  /// Packed Move With Zero Extend.
  | PMOVZXWQ = 555
  /// Multiply Packed Doubleword Integers.
  | PMULDQ = 556
  /// Packed Multiply High With Round and Scale.
  | PMULHRSW = 557
  /// Multiply Packed Unsigned Integers and Store High Result.
  | PMULHUW = 558
  /// Multiply Packed Signed Integers and Store High Result.
  | PMULHW = 559
  /// Multiply Packed Integers and Store Low Result.
  | PMULLD = 560
  /// Multiply Packed Signed Integers and Store Low Result.
  | PMULLW = 561
  /// Multiply Packed Unsigned Doubleword Integers.
  | PMULUDQ = 562
  /// Pop a Value From the Stack.
  | POP = 563
  /// Pop All General-Purpose Registers.
  | POPA = 564
  /// Pop All General-Purpose Registers.
  | POPAD = 565
  /// Return the Count of Number of Bits Set to 1.
  | POPCNT = 566
  /// Pop Stack Into EFLAGS Register.
  | POPF = 567
  /// Pop Stack Into EFLAGS Register.
  | POPFD = 568
  /// Pop Stack Into EFLAGS Register.
  | POPFQ = 569
  /// Bitwise Logical OR.
  | POR = 570
  /// Prefetch Data Into Caches.
  | PREFETCHIT0 = 571
  /// Prefetch Data Into Caches.
  | PREFETCHIT1 = 572
  /// Prefetch Data Into Caches.
  | PREFETCHNTA = 573
  /// Prefetch Data Into Caches.
  | PREFETCHT0 = 574
  /// Prefetch Data Into Caches.
  | PREFETCHT1 = 575
  /// Prefetch Data Into Caches.
  | PREFETCHT2 = 576
  /// Prefetch Data Into Caches in Anticipation of a Write.
  | PREFETCHW = 577
  /// Prefetch Vector Data Into Caches With Intent to Write and T1 Hint.
  | PREFETCHWT1 = 578
  /// Compute Sum of Absolute Differences.
  | PSADBW = 579
  /// Packed Shuffle Bytes.
  | PSHUFB = 580
  /// Shuffle Packed Doublewords.
  | PSHUFD = 581
  /// Shuffle Packed High Words.
  | PSHUFHW = 582
  /// Shuffle Packed Low Words.
  | PSHUFLW = 583
  /// Shuffle Packed Words.
  | PSHUFW = 584
  /// Packed SIGN.
  | PSIGNB = 585
  /// Packed SIGN.
  | PSIGND = 586
  /// Packed SIGN.
  | PSIGNW = 587
  /// Shift Packed Data Left Logical.
  | PSLLD = 588
  /// Shift Double Quadword Left Logical.
  | PSLLDQ = 589
  /// Shift Packed Data Left Logical.
  | PSLLQ = 590
  /// Shift Packed Data Left Logical.
  | PSLLW = 591
  /// Shift Packed Data Right Arithmetic.
  | PSRAD = 592
  /// Shift Packed Data Right Arithmetic.
  | PSRAW = 593
  /// Shift Packed Data Right Logical.
  | PSRLD = 594
  /// Shift Double Quadword Right Logical.
  | PSRLDQ = 595
  /// Shift Packed Data Right Logical.
  | PSRLQ = 596
  /// Shift Packed Data Right Logical.
  | PSRLW = 597
  /// Subtract Packed Integers.
  | PSUBB = 598
  /// Subtract Packed Integers.
  | PSUBD = 599
  /// Subtract Packed Quadword Integers.
  | PSUBQ = 600
  /// Subtract Packed Signed Integers With Signed Saturation.
  | PSUBSB = 601
  /// Subtract Packed Signed Integers With Signed Saturation.
  | PSUBSW = 602
  /// Subtract Packed Unsigned Integers With Unsigned Saturation.
  | PSUBUSB = 603
  /// Subtract Packed Unsigned Integers With Unsigned Saturation.
  | PSUBUSW = 604
  /// Subtract Packed Integers.
  | PSUBW = 605
  /// Logical Compare.
  | PTEST = 606
  /// Write Data to a Processor Trace Packet.
  | PTWRITE = 607
  /// Unpack High Data.
  | PUNPCKHBW = 608
  /// Unpack High Data.
  | PUNPCKHDQ = 609
  /// Unpack High Data.
  | PUNPCKHQDQ = 610
  /// Unpack High Data.
  | PUNPCKHWD = 611
  /// Unpack Low Data.
  | PUNPCKLBW = 612
  /// Unpack Low Data.
  | PUNPCKLDQ = 613
  /// Unpack Low Data.
  | PUNPCKLQDQ = 614
  /// Unpack Low Data.
  | PUNPCKLWD = 615
  /// Push Word, Doubleword, or Quadword Onto the Stack.
  | PUSH = 616
  /// Push All General-Purpose Registers.
  | PUSHA = 617
  /// Push All General-Purpose Registers.
  | PUSHAD = 618
  /// Push EFLAGS Register Onto the Stack.
  | PUSHF = 619
  /// Push EFLAGS Register Onto the Stack.
  | PUSHFD = 620
  /// Push EFLAGS Register Onto the Stack.
  | PUSHFQ = 621
  /// Logical Exclusive OR.
  | PXOR = 622
  /// Rotate.
  | RCL = 623
  /// Compute Reciprocals of Packed Single Precision Floating-Point Values.
  | RCPPS = 624
  /// Compute Reciprocal of Scalar Single Precision Floating-Point Values.
  | RCPSS = 625
  /// Rotate.
  | RCR = 626
  /// Read FS/GS Segment Base.
  | RDFSBASE = 627
  /// Read FS/GS Segment Base.
  | RDGSBASE = 628
  /// Read From Model Specific Register.
  | RDMSR = 629
  /// Read List of Model Specific Registers.
  | RDMSRLIST = 630
  /// Read Processor ID.
  | RDPID = 631
  /// Read Protection Key Rights for User Pages.
  | RDPKRU = 632
  /// Read Performance-Monitoring Counters.
  | RDPMC = 633
  /// Read Random Number.
  | RDRAND = 634
  /// Read Random SEED.
  | RDSEED = 635
  /// Read Shadow Stack Pointer.
  | RDSSPD = 636
  /// Read Shadow Stack Pointer.
  | RDSSPQ = 637
  /// Read Time-Stamp Counter.
  | RDTSC = 638
  /// Read Time-Stamp Counter and Processor ID.
  | RDTSCP = 639
  /// Return From Procedure.
  | RET = 640
  /// Rotate.
  | ROL = 641
  /// Rotate.
  | ROR = 642
  /// Rotate Right Logical Without Affecting Flags.
  | RORX = 643
  /// Round Packed Double Precision Floating-Point Values.
  | ROUNDPD = 644
  /// Round Packed Single Precision Floating-Point Values.
  | ROUNDPS = 645
  /// Round Scalar Double Precision Floating-Point Values.
  | ROUNDSD = 646
  /// Round Scalar Single Precision Floating-Point Values.
  | ROUNDSS = 647
  /// Resume From System Management Mode.
  | RSM = 648
  /// Compute Reciprocals of Square Roots of Packed Single Precision
  /// Floating-Point Values.
  | RSQRTPS = 649
  /// Compute Reciprocal of Square Root of Scalar Single Precision
  /// Floating-Point Value.
  | RSQRTSS = 650
  /// Restore Saved Shadow Stack Pointer.
  | RSTORSSP = 651
  /// Store AH Into Flags.
  | SAHF = 652
  /// Shift.
  | SHL = 653
  | SAL = 653
  /// Shift.
  | SAR = 654
  /// Shift Without Affecting Flags.
  | SARX = 655
  /// Save Previous Shadow Stack Pointer.
  | SAVEPREVSSP = 656
  /// Integer Subtraction With Borrow.
  | SBB = 657
  /// Scan String.
  | SCAS = 658
  /// Scan String.
  | SCASB = 659
  /// Scan String.
  | SCASD = 660
  /// Scan String.
  | SCASQ = 661
  /// Scan String.
  | SCASW = 662
  /// Send User Interprocessor Interrupt.
  | SENDUIPI = 663
  /// Serialize Instruction Execution.
  | SERIALIZE = 664
  /// Set Byte on Condition.
  | SETA = 665
  | SETNBE = 665
  /// Set Byte on Condition.
  | SETNB = 666
  | SETAE = 666
  | SETNC = 666
  /// Set Byte on Condition.
  | SETB = 667
  | SETC = 667
  | SETNAE = 667
  /// Set Byte on Condition.
  | SETBE = 668
  | SETNA = 668
  /// Set Byte on Condition.
  | SETZ = 669
  | SETE = 669
  /// Set Byte on Condition.
  | SETG = 670
  | SETNLE = 670
  /// Set Byte on Condition.
  | SETNL = 671
  | SETGE = 671
  /// Set Byte on Condition.
  | SETL = 672
  | SETNGE = 672
  /// Set Byte on Condition.
  | SETLE = 673
  | SETNG = 673
  /// Set Byte on Condition.
  | SETNZ = 674
  | SETNE = 674
  /// Set Byte on Condition.
  | SETNO = 675
  /// Set Byte on Condition.
  | SETNP = 676
  | SETPO = 676
  /// Set Byte on Condition.
  | SETNS = 677
  /// Set Byte on Condition.
  | SETO = 678
  /// Set Byte on Condition.
  | SETP = 679
  | SETPE = 679
  /// Set Byte on Condition.
  | SETS = 680
  /// Mark Shadow Stack Busy.
  | SETSSBSY = 681
  /// Store Fence.
  | SFENCE = 682
  /// Store Global Descriptor Table Register.
  | SGDT = 683
  /// Perform an Intermediate Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG1 = 684
  /// Perform a Final Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG2 = 685
  /// Calculate SHA1 State Variable E After Four Rounds.
  | SHA1NEXTE = 686
  /// Perform Four Rounds of SHA1 Operation.
  | SHA1RNDS4 = 687
  /// Perform an Intermediate Calculation for the Next Four SHA256 Message
  /// Dwords.
  | SHA256MSG1 = 688
  /// Perform a Final Calculation for the Next Four SHA256 Message Dwords.
  | SHA256MSG2 = 689
  /// Perform Two Rounds of SHA256 Operation.
  | SHA256RNDS2 = 690
  /// Double Precision Shift Left.
  | SHLD = 691
  /// Shift Without Affecting Flags.
  | SHLX = 692
  /// Shift.
  | SHR = 693
  /// Double Precision Shift Right.
  | SHRD = 694
  /// Shift Without Affecting Flags.
  | SHRX = 695
  /// Packed Interleave Shuffle of Pairs of Double Precision Floating-Point
  /// Values.
  | SHUFPD = 696
  /// Packed Interleave Shuffle of Quadruplets of Single Precision
  /// Floating-Point Values.
  | SHUFPS = 697
  /// Store Interrupt Descriptor Table Register.
  | SIDT = 698
  /// Store Local Descriptor Table Register.
  | SLDT = 699
  /// Chinese national cryptographic algorithms.
  | SM2 = 700
  /// Store Machine Status Word.
  | SMSW = 701
  /// Square Root of Double Precision Floating-Point Values.
  | SQRTPD = 702
  /// Square Root of Single Precision Floating-Point Values.
  | SQRTPS = 703
  /// Compute Square Root of Scalar Double Precision Floating-Point Value.
  | SQRTSD = 704
  /// Compute Square Root of Scalar Single Precision Value.
  | SQRTSS = 705
  /// Set AC Flag in EFLAGS Register.
  | STAC = 706
  /// Set Carry Flag.
  | STC = 707
  /// Set Direction Flag.
  | STD = 708
  /// Set Interrupt Flag.
  | STI = 709
  /// Store MXCSR Register State.
  | STMXCSR = 710
  /// Store String.
  | STOS = 711
  /// Store String.
  | STOSB = 712
  /// Store String.
  | STOSD = 713
  /// Store String.
  | STOSQ = 714
  /// Store String.
  | STOSW = 715
  /// Store Task Register.
  | STR = 716
  /// Store Tile Configuration.
  | STTILECFG = 717
  /// Set User Interrupt Flag.
  | STUI = 718
  /// Subtract.
  | SUB = 719
  /// Subtract Packed Double Precision Floating-Point Values.
  | SUBPD = 720
  /// Subtract Packed Single Precision Floating-Point Values.
  | SUBPS = 721
  /// Subtract Scalar Double Precision Floating-Point Value.
  | SUBSD = 722
  /// Subtract Scalar Single Precision Floating-Point Value.
  | SUBSS = 723
  /// Swap GS Base Register.
  | SWAPGS = 724
  /// Fast System Call.
  | SYSCALL = 725
  /// Fast System Call.
  | SYSENTER = 726
  /// Fast Return from Fast System Call.
  | SYSEXIT = 727
  /// Return From Fast System Call.
  | SYSRET = 728
  /// Dot Product of BF16 Tiles Accumulated into Packed Single Precision Tile.
  | TDPBF16PS = 729
  /// Dot Product of Signed/Unsigned Bytes with Dword Accumulation.
  | TDPBSSD = 730
  /// Dot Product of Signed/Unsigned Bytes with Dword Accumulation.
  | TDPBSUD = 731
  /// Dot Product of Signed/Unsigned Bytes with Dword Accumulation.
  | TDPBUSD = 732
  /// Dot Product of Signed/Unsigned Bytes with Dword Accumulation.
  | TDPBUUD = 733
  /// Dot Product of FP16 Tiles Accumulated into Packed Single Precision Tile.
  | TDPFP16PS = 734
  /// Logical Compare.
  | TEST = 735
  /// Determine User Interrupt Flag.
  | TESTUI = 736
  /// Load Tile.
  | TILELOADD = 737
  /// Load Tile.
  | TILELOADDT1 = 738
  /// Release Tile.
  | TILERELEASE = 739
  /// Store Tile.
  | TILESTORED = 740
  /// Zero Tile.
  | TILEZERO = 741
  /// Timed PAUSE.
  | TPAUSE = 742
  /// Count the Number of Trailing Zero Bits.
  | TZCNT = 743
  /// Unordered Compare Scalar Double Precision Floating-Point Values and Set
  /// EFLAGS.
  | UCOMISD = 744
  /// Unordered Compare Scalar Single Precision Floating-Point Values and Set
  /// EFLAGS.
  | UCOMISS = 745
  /// Undefined Instruction.
  | UD0 = 746
  /// Undefined Instruction.
  | UD1 = 747
  /// Undefined Instruction.
  | UD2 = 748
  /// Undefined Instruction.
  | UDB = 749
  /// User-Interrupt Return.
  | UIRET = 750
  /// User Level Set Up Monitor Address.
  | UMONITOR = 751
  /// User Level Monitor Wait.
  | UMWAIT = 752
  /// Unpack and Interleave High Packed Double Precision Floating-Point Values.
  | UNPCKHPD = 753
  /// Unpack and Interleave High Packed Single Precision Floating-Point Values.
  | UNPCKHPS = 754
  /// Unpack and Interleave Low Packed Double Precision Floating-Point Values.
  | UNPCKLPD = 755
  /// Unpack and Interleave Low Packed Single Precision Floating-Point Values.
  | UNPCKLPS = 756
  /// Packed Single Precision Floating-Point Fused Multiply-Add (4-Iterations).
  | V4FMADDPS = 757
  /// Scalar Single Precision Floating-Point Fused Multiply-Add (4-Iterations).
  | V4FMADDSS = 758
  /// Packed Single Precision Floating-Point Fused Multiply-Add (4-Iterations).
  | V4FNMADDPS = 759
  /// Scalar Single Precision Floating-Point Fused Multiply-Add (4-Iterations).
  | V4FNMADDSS = 760
  /// Add Packed Double Precision Floating-Point Values.
  | VADDPD = 761
  /// Add Packed FP16 Values.
  | VADDPH = 762
  /// Add Packed Single Precision Floating-Point Values.
  | VADDPS = 763
  /// Add Scalar Double Precision Floating-Point Values.
  | VADDSD = 764
  /// Add Scalar FP16 Values.
  | VADDSH = 765
  /// Add Scalar Single Precision Floating-Point Values.
  | VADDSS = 766
  /// Packed Double Precision Floating-Point Add/Subtract.
  | VADDSUBPD = 767
  /// Packed Single Precision Floating-Point Add/Subtract.
  | VADDSUBPS = 768
  /// Perform One Round of an AES Decryption Flow.
  | VAESDEC = 769
  /// Perform Last Round of an AES Decryption Flow.
  | VAESDECLAST = 770
  /// Perform One Round of an AES Encryption Flow.
  | VAESENC = 771
  /// Perform Last Round of an AES Encryption Flow.
  | VAESENCLAST = 772
  /// Perform the AES InvMixColumn Transformation.
  | VAESIMC = 773
  /// AES Round Key Generation Assist.
  | VAESKEYGENASSIST = 774
  /// Align Doubleword/Quadword Vectors.
  | VALIGND = 775
  /// Align Doubleword/Quadword Vectors.
  | VALIGNQ = 776
  /// Bitwise Logical AND NOT of Packed Double Precision Floating-Point Values.
  | VANDNPD = 777
  /// Bitwise Logical AND NOT of Packed Single Precision Floating-Point Values.
  | VANDNPS = 778
  /// Bitwise Logical AND of Packed Double Precision Floating-Point Values.
  | VANDPD = 779
  /// Bitwise Logical AND of Packed Single Precision Floating-Point Values.
  | VANDPS = 780
  /// Load BF16 Element and Convert to FP32 Element With Broadcast.
  | VBCSTNEBF162PS = 781
  /// Load FP16 Element and Convert to FP32 Element with Broadcast.
  | VBCSTNESH2PS = 782
  /// Blend Float64/Float32 Vectors Using an OpMask Control.
  | VBLENDMPD = 783
  /// Blend Float64/Float32 Vectors Using an OpMask Control.
  | VBLENDMPS = 784
  /// Blend Packed Double Precision Floating-Point Values.
  | VBLENDPD = 785
  /// Blend Packed Single Precision Floating-Point Values.
  | VBLENDPS = 786
  /// Variable Blend Packed Double Precision Floating-Point Values.
  | VBLENDVPD = 787
  /// Variable Blend Packed Single Precision Floating-Point Values.
  | VBLENDVPS = 788
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTF128 = 789
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTF32X2 = 790
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTF32X4 = 791
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTF32X8 = 792
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTF64X2 = 793
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTF64X4 = 794
  /// Load Integer and Broadcast.
  | VBROADCASTI128 = 795
  /// Load Integer and Broadcast.
  | VBROADCASTI32X2 = 796
  /// Load Integer and Broadcast.
  | VBROADCASTI32X4 = 797
  /// Load Integer and Broadcast.
  | VBROADCASTI32X8 = 798
  /// Load Integer and Broadcast.
  | VBROADCASTI64X2 = 799
  /// Load Integer and Broadcast.
  | VBROADCASTI64X4 = 800
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTSD = 801
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTSS = 802
  /// Compare Packed Double Precision Floating-Point Values.
  | VCMPPD = 803
  /// Compare Packed FP16 Values.
  | VCMPPH = 804
  /// Compare Packed Single Precision Floating-Point Values.
  | VCMPPS = 805
  /// Compare Scalar Double Precision Floating-Point Value.
  | VCMPSD = 806
  /// Compare Scalar FP16 Values.
  | VCMPSH = 807
  /// Compare Scalar Single Precision Floating-Point Value.
  | VCMPSS = 808
  /// Compare Scalar Ordered Double Precision Floating-Point Values and Set
  /// EFLAGS.
  | VCOMISD = 809
  /// Compare Scalar Ordered FP16 Values and Set EFLAGS.
  | VCOMISH = 810
  /// Compare Scalar Ordered Single Precision Floating-Point Values and Set
  /// EFLAGS.
  | VCOMISS = 811
  /// Store Sparse Packed Double Precision Floating-Point Values Into Dense
  /// Memory.
  | VCOMPRESSPD = 812
  /// Store Sparse Packed Single Precision Floating-Point Values Into Dense
  /// Memory.
  | VCOMPRESSPS = 813
  /// Convert Packed Doubleword Integers to Packed Double Precision
  /// Floating-Point Values.
  | VCVTDQ2PD = 814
  /// Convert Packed Signed Doubleword Integers to Packed FP16 Values.
  | VCVTDQ2PH = 815
  /// Convert Packed Doubleword Integers to Packed Single Precision
  /// Floating-Point Values.
  | VCVTDQ2PS = 816
  /// Convert Two Packed Single Data to One Packed BF16 Data.
  | VCVTNE2PS2BF16 = 817
  /// Convert Even Elements of Packed BF16 Values to FP32 Values.
  | VCVTNEEBF162PS = 818
  /// Convert Even Elements of Packed FP16 Values to FP32 Values.
  | VCVTNEEPH2PS = 819
  /// Convert Odd Elements of Packed BF16 Values to FP32 Values.
  | VCVTNEOBF162PS = 820
  /// Convert Odd Elements of Packed FP16 Values to FP32 Values.
  | VCVTNEOPH2PS = 821
  /// Convert Packed Single Data to Packed BF16 Data.
  | VCVTNEPS2BF16 = 822
  /// Convert Packed Double Precision Floating-Point Values to Packed Doubleword
  /// Integers.
  | VCVTPD2DQ = 823
  /// Convert Packed Double Precision FP Values to Packed FP16 Values.
  | VCVTPD2PH = 824
  /// Convert Packed Double Precision Floating-Point Values to Packed Single
  /// Precision Floating-Point Values.
  | VCVTPD2PS = 825
  /// Convert Packed Double Precision Floating-Point Values to Packed Quadword
  /// Integers.
  | VCVTPD2QQ = 826
  /// Convert Packed Double Precision Floating-Point Values to Packed Unsigned
  /// Doubleword Integers.
  | VCVTPD2UDQ = 827
  /// Convert Packed Double Precision Floating-Point Values to Packed Unsigned
  /// Quadword Integers.
  | VCVTPD2UQQ = 828
  /// Convert Packed FP16 Values to Signed Doubleword Integers.
  | VCVTPH2DQ = 829
  /// Convert Packed FP16 Values to FP64 Values.
  | VCVTPH2PD = 830
  /// Convert Packed FP16 Values to Single Precision Floating-Point Values.
  | VCVTPH2PS = 831
  /// Convert Packed FP16 Values to Single Precision Floating-Point Values.
  | VCVTPH2PSX = 832
  /// Convert Packed FP16 Values to Signed Quadword Integer Values.
  | VCVTPH2QQ = 833
  /// Convert Packed FP16 Values to Unsigned Doubleword Integers.
  | VCVTPH2UDQ = 834
  /// Convert Packed FP16 Values to Unsigned Quadword Integers.
  | VCVTPH2UQQ = 835
  /// Convert Packed FP16 Values to Unsigned Word Integers.
  | VCVTPH2UW = 836
  /// Convert Packed FP16 Values to Signed Word Integers.
  | VCVTPH2W = 837
  /// Convert Packed Single Precision Floating-Point Values to Packed Signed
  /// Doubleword Integer Values.
  | VCVTPS2DQ = 838
  /// Convert Packed Single Precision Floating-Point Values to Packed Double
  /// Precision Floating-Point Values.
  | VCVTPS2PD = 839
  /// Convert Single Precision FP Value to 16-bit FP Value.
  | VCVTPS2PH = 840
  /// Convert Packed Single Precision Floating-Point Values to Packed FP16
  /// Values.
  | VCVTPS2PHX = 841
  /// Convert Packed Single Precision Floating-Point Values to Packed Signed
  /// Quadword Integer Values.
  | VCVTPS2QQ = 842
  /// Convert Packed Single Precision Floating-Point Values to Packed Unsigned
  /// Doubleword Integer Values.
  | VCVTPS2UDQ = 843
  /// Convert Packed Single Precision Floating-Point Values to Packed Unsigned
  /// Quadword Integer Values.
  | VCVTPS2UQQ = 844
  /// Convert Packed Quadword Integers to Packed Double Precision Floating-Point
  /// Values.
  | VCVTQQ2PD = 845
  /// Convert Packed Signed Quadword Integers to Packed FP16 Values.
  | VCVTQQ2PH = 846
  /// Convert Packed Quadword Integers to Packed Single Precision Floating-Point
  /// Values.
  | VCVTQQ2PS = 847
  /// Convert Low FP64 Value to an FP16 Value.
  | VCVTSD2SH = 848
  /// Convert Scalar Double Precision Floating-Point Value to Signed Integer.
  | VCVTSD2SI = 849
  /// Convert Scalar Double Precision Floating-Point Value to Scalar Single
  /// Precision Floating-Point Value.
  | VCVTSD2SS = 850
  /// Convert Scalar Double Precision Floating-Point Value to Unsigned Integer.
  | VCVTSD2USI = 851
  /// Convert Low FP16 Value to an FP64 Value.
  | VCVTSH2SD = 852
  /// Convert Low FP16 Value to Signed Integer.
  | VCVTSH2SI = 853
  /// Convert Low FP16 Value to FP32 Value.
  | VCVTSH2SS = 854
  /// Convert Low FP16 Value to Unsigned Integer.
  | VCVTSH2USI = 855
  /// Convert Signed Integer to Scalar Double Precision Floating-Point Value.
  | VCVTSI2SD = 856
  /// Convert a Signed Doubleword/Quadword Integer to an FP16 Value.
  | VCVTSI2SH = 857
  /// Convert Signed Integer to Scalar Single Precision Floating-Point Value.
  | VCVTSI2SS = 858
  /// Convert Scalar Single Precision Floating-Point Value to Scalar Double
  /// Precision Floating-Point Value.
  | VCVTSS2SD = 859
  /// Convert Low FP32 Value to an FP16 Value.
  | VCVTSS2SH = 860
  /// Convert Scalar Single Precision Floating-Point Value to Signed Integer.
  | VCVTSS2SI = 861
  /// Convert Scalar Single Precision Floating-Point Value to Unsigned
  /// Doubleword Integer.
  | VCVTSS2USI = 862
  /// Convert with Truncation Packed Double Precision Floating-Point Values to
  /// Packed Doubleword Integers.
  | VCVTTPD2DQ = 863
  /// Convert With Truncation Packed Double Precision Floating-Point Values to
  /// Packed Quadword Integers.
  | VCVTTPD2QQ = 864
  /// Convert With Truncation Packed Double Precision Floating-Point Values to
  /// Packed Unsigned Doubleword Integers.
  | VCVTTPD2UDQ = 865
  /// Convert With Truncation Packed Double Precision Floating-Point Values to
  /// Packed Unsigned Quadword Integers.
  | VCVTTPD2UQQ = 866
  /// Convert with Truncation Packed FP16 Values to Signed Doubleword Integers.
  | VCVTTPH2DQ = 867
  /// Convert with Truncation Packed FP16 Values to Signed Quadword Integers.
  | VCVTTPH2QQ = 868
  /// Convert with Truncation Packed FP16 Values to Unsigned Doubleword
  /// Integers.
  | VCVTTPH2UDQ = 869
  /// Convert with Truncation Packed FP16 Values to Unsigned Quadword Integers.
  | VCVTTPH2UQQ = 870
  /// Convert Packed FP16 Values to Unsigned Word Integers.
  | VCVTTPH2UW = 871
  /// Convert Packed FP16 Values to Signed Word Integers.
  | VCVTTPH2W = 872
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Signed Doubleword Integer Values.
  | VCVTTPS2DQ = 873
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Signed Quadword Integer Values.
  | VCVTTPS2QQ = 874
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Unsigned Doubleword Integer Values.
  | VCVTTPS2UDQ = 875
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Unsigned Quadword Integer Values.
  | VCVTTPS2UQQ = 876
  /// Convert With Truncation Scalar Double Precision Floating-Point Value to
  /// Signed Integer.
  | VCVTTSD2SI = 877
  /// Convert With Truncation Scalar Double Precision Floating-Point Value to
  /// Unsigned Integer.
  | VCVTTSD2USI = 878
  /// Convert with Truncation Low FP16 Value to a Signed Integer.
  | VCVTTSH2SI = 879
  /// Convert with Truncation Low FP16 Value to an Unsigned Integer.
  | VCVTTSH2USI = 880
  /// Convert With Truncation Scalar Single Precision Floating-Point Value to
  /// Signed Integer.
  | VCVTTSS2SI = 881
  /// Convert With Truncation Scalar Single Precision Floating-Point Value to
  /// Unsigned Integer.
  | VCVTTSS2USI = 882
  /// Convert Packed Unsigned Doubleword Integers to Packed Double Precision
  /// Floating-Point Values.
  | VCVTUDQ2PD = 883
  /// Convert Packed Unsigned Doubleword Integers to Packed FP16 Values.
  | VCVTUDQ2PH = 884
  /// Convert Packed Unsigned Doubleword Integers to Packed Single Precision
  /// Floating-Point Values.
  | VCVTUDQ2PS = 885
  /// Convert Packed Unsigned Quadword Integers to Packed Double Precision
  /// Floating-Point Values.
  | VCVTUQQ2PD = 886
  /// Convert Packed Unsigned Quadword Integers to Packed FP16 Values.
  | VCVTUQQ2PH = 887
  /// Convert Packed Unsigned Quadword Integers to Packed Single Precision
  /// Floating-Point Values.
  | VCVTUQQ2PS = 888
  /// Convert Unsigned Integer to Scalar Double Precision Floating-Point Value.
  | VCVTUSI2SD = 889
  /// Convert Unsigned Doubleword Integer to an FP16 Value.
  | VCVTUSI2SH = 890
  /// Convert Unsigned Integer to Scalar Single Precision Floating-Point Value.
  | VCVTUSI2SS = 891
  /// Convert Packed Unsigned Word Integers to FP16 Values.
  | VCVTUW2PH = 892
  /// Convert Packed Signed Word Integers to FP16 Values.
  | VCVTW2PH = 893
  /// Double Block Packed Sum-Absolute-Differences (SAD) on Unsigned Bytes.
  | VDBPSADBW = 894
  /// Divide Packed Double Precision Floating-Point Values.
  | VDIVPD = 895
  /// Divide Packed FP16 Values.
  | VDIVPH = 896
  /// Divide Packed Single Precision Floating-Point Values.
  | VDIVPS = 897
  /// Divide Scalar Double Precision Floating-Point Value.
  | VDIVSD = 898
  /// Divide Scalar FP16 Values.
  | VDIVSH = 899
  /// Divide Scalar Single Precision Floating-Point Values.
  | VDIVSS = 900
  /// Dot Product of BF16 Pairs Accumulated Into Packed Single Precision.
  | VDPBF16PS = 901
  /// Dot Product of Packed Double Precision Floating-Point Values.
  | VDPPD = 902
  /// Dot Product of Packed Single Precision Floating-Point Values.
  | VDPPS = 903
  /// Verify a Segment for Reading or Writing.
  | VERR = 904
  /// Verify a Segment for Reading or Writing.
  | VERW = 905
  /// Approximation to the Exponential 2^x of Packed Double Precision
  /// Floating-Point Values With Less Than 2^-23 Relative Error.
  | VEXP2PD = 906
  /// Approximation to the Exponential 2^x of Packed Single Precision
  /// Floating-Point Values With Less Than 2^-23 Relative Error.
  | VEXP2PS = 907
  /// Load Sparse Packed Double Precision Floating-Point Values From Dense
  /// Memory.
  | VEXPANDPD = 908
  /// Load Sparse Packed Single Precision Floating-Point Values From Dense
  /// Memory.
  | VEXPANDPS = 909
  /// Extract Packed Floating-Point Values.
  | VEXTRACTF128 = 910
  /// Extract Packed Floating-Point Values.
  | VEXTRACTF32X4 = 911
  /// Extract Packed Floating-Point Values.
  | VEXTRACTF32X8 = 912
  /// Extract Packed Floating-Point Values.
  | VEXTRACTF64X2 = 913
  /// Extract Packed Floating-Point Values.
  | VEXTRACTF64X4 = 914
  /// Extract Packed Integer Values.
  | VEXTRACTI128 = 915
  /// Extract Packed Integer Values.
  | VEXTRACTI32X4 = 916
  /// Extract Packed Integer Values.
  | VEXTRACTI32X8 = 917
  /// Extract Packed Integer Values.
  | VEXTRACTI64X2 = 918
  /// Extract Packed Integer Values.
  | VEXTRACTI64X4 = 919
  /// Extract Packed Floating-Point Values.
  | VEXTRACTPS = 920
  /// Complex Multiply and Accumulate FP16 Values.
  | VFCMADDCPH = 921
  /// Complex Multiply and Accumulate Scalar FP16 Values.
  | VFCMADDCSH = 922
  /// Complex Multiply FP16 Values.
  | VFCMULCPH = 923
  /// Complex Multiply Scalar FP16 Values.
  | VFCMULCSH = 924
  /// Fix Up Special Packed Float64 Values.
  | VFIXUPIMMPD = 925
  /// Fix Up Special Packed Float32 Values.
  | VFIXUPIMMPS = 926
  /// Fix Up Special Scalar Float64 Value.
  | VFIXUPIMMSD = 927
  /// Fix Up Special Scalar Float32 Value.
  | VFIXUPIMMSS = 928
  /// Fused Multiply-Add of Packed Double Precision Floating-Point Values.
  | VFMADD132PD = 929
  /// Fused Multiply-Add of Packed FP16 Values.
  | VFMADD132PH = 930
  /// Fused Multiply-Add of Packed Single Precision Floating-Point Values.
  | VFMADD132PS = 931
  /// Fused Multiply-Add of Scalar Double Precision Floating-Point Values.
  | VFMADD132SD = 932
  /// Fused Multiply-Add of Scalar FP16 Values.
  | VFMADD132SH = 933
  /// Fused Multiply-Add of Scalar Single Precision Floating-Point Values.
  | VFMADD132SS = 934
  /// Fused Multiply-Add of Packed Double Precision Floating-Point Values.
  | VFMADD213PD = 935
  /// Fused Multiply-Add of Packed FP16 Values.
  | VFMADD213PH = 936
  /// Fused Multiply-Add of Packed Single Precision Floating-Point Values.
  | VFMADD213PS = 937
  /// Fused Multiply-Add of Scalar Double Precision Floating-Point Values.
  | VFMADD213SD = 938
  /// Fused Multiply-Add of Scalar FP16 Values.
  | VFMADD213SH = 939
  /// Fused Multiply-Add of Scalar Single Precision Floating-Point Values.
  | VFMADD213SS = 940
  /// Fused Multiply-Add of Packed Double Precision Floating-Point Values.
  | VFMADD231PD = 941
  /// Fused Multiply-Add of Packed FP16 Values.
  | VFMADD231PH = 942
  /// Fused Multiply-Add of Packed Single Precision Floating-Point Values.
  | VFMADD231PS = 943
  /// Fused Multiply-Add of Scalar Double Precision Floating-Point Values.
  | VFMADD231SD = 944
  /// Fused Multiply-Add of Scalar FP16 Values.
  | VFMADD231SH = 945
  /// Fused Multiply-Add of Scalar Single Precision Floating-Point Values.
  | VFMADD231SS = 946
  /// Complex Multiply and Accumulate FP16 Values.
  | VFMADDCPH = 947
  /// Complex Multiply and Accumulate Scalar FP16 Values.
  | VFMADDCSH = 948
  /// Multiply and Add Packed Double-Precision Floating-Point(Only AMD).
  | VFMADDPD = 949
  /// Multiply and Add Packed Single-Precision Floating-Point(Only AMD).
  | VFMADDPS = 950
  /// Multiply and Add Scalar Double-Precision Floating-Point(Only AMD).
  | VFMADDSD = 951
  /// Multiply and Add Scalar Single-Precision Floating-Point(Only AMD).
  | VFMADDSS = 952
  /// Fused Multiply-Alternating Add/Subtract of Packed Double Precision
  /// Floating-Point Values.
  | VFMADDSUB132PD = 953
  /// Fused Multiply-Alternating Add/Subtract of Packed FP16 Values.
  | VFMADDSUB132PH = 954
  /// Fused Multiply-Alternating Add/Subtract of Packed Single Precision
  /// Floating-Point Values.
  | VFMADDSUB132PS = 955
  /// Fused Multiply-Alternating Add/Subtract of Packed Double Precision
  /// Floating-Point Values.
  | VFMADDSUB213PD = 956
  /// Fused Multiply-Alternating Add/Subtract of Packed FP16 Values.
  | VFMADDSUB213PH = 957
  /// Fused Multiply-Alternating Add/Subtract of Packed Single Precision
  /// Floating-Point Values.
  | VFMADDSUB213PS = 958
  /// Fused Multiply-Alternating Add/Subtract of Packed Double Precision
  /// Floating-Point Values.
  | VFMADDSUB231PD = 959
  /// Fused Multiply-Alternating Add/Subtract of Packed FP16 Values.
  | VFMADDSUB231PH = 960
  /// Fused Multiply-Alternating Add/Subtract of Packed Single Precision
  /// Floating-Point Values.
  | VFMADDSUB231PS = 961
  /// Fused Multiply-Subtract of Packed Double Precision Floating-Point Values.
  | VFMSUB132PD = 962
  /// Fused Multiply-Subtract of Packed FP16 Values.
  | VFMSUB132PH = 963
  /// Fused Multiply-Subtract of Packed Single Precision Floating-Point Values.
  | VFMSUB132PS = 964
  /// Fused Multiply-Subtract of Scalar Double Precision Floating-Point Values.
  | VFMSUB132SD = 965
  /// Fused Multiply-Subtract of Scalar FP16 Values.
  | VFMSUB132SH = 966
  /// Fused Multiply-Subtract of Scalar Single Precision Floating-Point Values.
  | VFMSUB132SS = 967
  /// Fused Multiply-Subtract of Packed Double Precision Floating-Point Values.
  | VFMSUB213PD = 968
  /// Fused Multiply-Subtract of Packed FP16 Values.
  | VFMSUB213PH = 969
  /// Fused Multiply-Subtract of Packed Single Precision Floating-Point Values.
  | VFMSUB213PS = 970
  /// Fused Multiply-Subtract of Scalar Double Precision Floating-Point Values.
  | VFMSUB213SD = 971
  /// Fused Multiply-Subtract of Scalar FP16 Values.
  | VFMSUB213SH = 972
  /// Fused Multiply-Subtract of Scalar Single Precision Floating-Point Values.
  | VFMSUB213SS = 973
  /// Fused Multiply-Subtract of Packed Double Precision Floating-Point Values.
  | VFMSUB231PD = 974
  /// Fused Multiply-Subtract of Packed FP16 Values.
  | VFMSUB231PH = 975
  /// Fused Multiply-Subtract of Packed Single Precision Floating-Point Values.
  | VFMSUB231PS = 976
  /// Fused Multiply-Subtract of Scalar Double Precision Floating-Point Values.
  | VFMSUB231SD = 977
  /// Fused Multiply-Subtract of Scalar FP16 Values.
  | VFMSUB231SH = 978
  /// Fused Multiply-Subtract of Scalar Single Precision Floating-Point Values.
  | VFMSUB231SS = 979
  /// Fused Multiply-Alternating Subtract/Add of Packed Double Precision
  /// Floating-Point Values.
  | VFMSUBADD132PD = 980
  /// Fused Multiply-Alternating Subtract/Add of Packed FP16 Values.
  | VFMSUBADD132PH = 981
  /// Fused Multiply-Alternating Subtract/Add of Packed Single Precision
  /// Floating-Point Values.
  | VFMSUBADD132PS = 982
  /// Fused Multiply-Alternating Subtract/Add of Packed Double Precision
  /// Floating-Point Values.
  | VFMSUBADD213PD = 983
  /// Fused Multiply-Alternating Subtract/Add of Packed FP16 Values.
  | VFMSUBADD213PH = 984
  /// Fused Multiply-Alternating Subtract/Add of Packed Single Precision
  /// Floating-Point Values.
  | VFMSUBADD213PS = 985
  /// Fused Multiply-Alternating Subtract/Add of Packed Double Precision
  /// Floating-Point Values.
  | VFMSUBADD231PD = 986
  /// Fused Multiply-Alternating Subtract/Add of Packed FP16 Values.
  | VFMSUBADD231PH = 987
  /// Fused Multiply-Alternating Subtract/Add of Packed Single Precision
  /// Floating-Point Values.
  | VFMSUBADD231PS = 988
  /// Complex Multiply FP16 Values.
  | VFMULCPH = 989
  /// Complex Multiply Scalar FP16 Values.
  | VFMULCSH = 990
  /// Fused Negative Multiply-Add of Packed Double Precision Floating-Point
  /// Values.
  | VFNMADD132PD = 991
  /// Fused Multiply-Add of Packed FP16 Values.
  | VFNMADD132PH = 992
  /// Fused Negative Multiply-Add of Packed Single Precision Floating-Point
  /// Values.
  | VFNMADD132PS = 993
  /// Fused Negative Multiply-Add of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMADD132SD = 994
  /// Fused Multiply-Add of Scalar FP16 Values.
  | VFNMADD132SH = 995
  /// Fused Negative Multiply-Add of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMADD132SS = 996
  /// Fused Negative Multiply-Add of Packed Double Precision Floating-Point
  /// Values.
  | VFNMADD213PD = 997
  /// Fused Multiply-Add of Packed FP16 Values.
  | VFNMADD213PH = 998
  /// Fused Negative Multiply-Add of Packed Single Precision Floating-Point
  /// Values.
  | VFNMADD213PS = 999
  /// Fused Negative Multiply-Add of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMADD213SD = 1000
  /// Fused Multiply-Add of Scalar FP16 Values.
  | VFNMADD213SH = 1001
  /// Fused Negative Multiply-Add of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMADD213SS = 1002
  /// Fused Negative Multiply-Add of Packed Double Precision Floating-Point
  /// Values.
  | VFNMADD231PD = 1003
  /// Fused Multiply-Add of Packed FP16 Values.
  | VFNMADD231PH = 1004
  /// Fused Negative Multiply-Add of Packed Single Precision Floating-Point
  /// Values.
  | VFNMADD231PS = 1005
  /// Fused Negative Multiply-Add of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMADD231SD = 1006
  /// Fused Multiply-Add of Scalar FP16 Values.
  | VFNMADD231SH = 1007
  /// Fused Negative Multiply-Add of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMADD231SS = 1008
  /// Fused Negative Multiply-Subtract of Packed Double Precision Floating-Point
  /// Values.
  | VFNMSUB132PD = 1009
  /// Fused Multiply-Subtract of Packed FP16 Values.
  | VFNMSUB132PH = 1010
  /// Fused Negative Multiply-Subtract of Packed Single Precision Floating-Point
  /// Values.
  | VFNMSUB132PS = 1011
  /// Fused Negative Multiply-Subtract of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMSUB132SD = 1012
  /// Fused Multiply-Subtract of Scalar FP16 Values.
  | VFNMSUB132SH = 1013
  /// Fused Negative Multiply-Subtract of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMSUB132SS = 1014
  /// Fused Negative Multiply-Subtract of Packed Double Precision Floating-Point
  /// Values.
  | VFNMSUB213PD = 1015
  /// Fused Multiply-Subtract of Packed FP16 Values.
  | VFNMSUB213PH = 1016
  /// Fused Negative Multiply-Subtract of Packed Single Precision Floating-Point
  /// Values.
  | VFNMSUB213PS = 1017
  /// Fused Negative Multiply-Subtract of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMSUB213SD = 1018
  /// Fused Multiply-Subtract of Scalar FP16 Values.
  | VFNMSUB213SH = 1019
  /// Fused Negative Multiply-Subtract of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMSUB213SS = 1020
  /// Fused Negative Multiply-Subtract of Packed Double Precision Floating-Point
  /// Values.
  | VFNMSUB231PD = 1021
  /// Fused Multiply-Subtract of Packed FP16 Values.
  | VFNMSUB231PH = 1022
  /// Fused Negative Multiply-Subtract of Packed Single Precision Floating-Point
  /// Values.
  | VFNMSUB231PS = 1023
  /// Fused Negative Multiply-Subtract of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMSUB231SD = 1024
  /// Fused Multiply-Subtract of Scalar FP16 Values.
  | VFNMSUB231SH = 1025
  /// Fused Negative Multiply-Subtract of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMSUB231SS = 1026
  /// Tests Types of Packed Float64 Values.
  | VFPCLASSPD = 1027
  /// Test Types of Packed FP16 Values.
  | VFPCLASSPH = 1028
  /// Tests Types of Packed Float32 Values.
  | VFPCLASSPS = 1029
  /// Tests Type of a Scalar Float64 Value.
  | VFPCLASSSD = 1030
  /// Test Types of Scalar FP16 Values.
  | VFPCLASSSH = 1031
  /// Tests Type of a Scalar Float32 Value.
  | VFPCLASSSS = 1032
  /// Gather Packed Double Precision Floating-Point Values Using Signed
  /// Dword/Qword Indices.
  /// Gather Packed Single, Packed Double with Signed Dword Indices.
  | VGATHERDPD = 1033
  /// Gather Packed Single, Packed Double with Signed Dword Indices.
  /// Gather Packed Single Precision Floating-Point Values Using Signed
  /// Dword/Qword Indices.
  | VGATHERDPS = 1034
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T0 Hint.
  | VGATHERPF0DPD = 1035
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T0 Hint.
  | VGATHERPF0DPS = 1036
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T0 Hint.
  | VGATHERPF0QPD = 1037
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T0 Hint.
  | VGATHERPF0QPS = 1038
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T1 Hint.
  | VGATHERPF1DPD = 1039
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T1 Hint.
  | VGATHERPF1DPS = 1040
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T1 Hint.
  | VGATHERPF1QPD = 1041
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T1 Hint.
  | VGATHERPF1QPS = 1042
  /// Gather Packed Double Precision Floating-Point Values Using Signed
  /// Dword/Qword Indices.
  /// Gather Packed Single, Packed Double with Signed Qword Indices.
  | VGATHERQPD = 1043
  /// Gather Packed Single Precision Floating-Point Values Using Signed
  /// Dword/Qword Indices.
  /// Gather Packed Single, Packed Double with Signed Qword Indices.
  | VGATHERQPS = 1044
  /// Convert Exponents of Packed Double Precision Floating-Point Values to
  /// Double Precision Floating-Point Values.
  | VGETEXPPD = 1045
  /// Convert Exponents of Packed FP16 Values to FP16 Values.
  | VGETEXPPH = 1046
  /// Convert Exponents of Packed Single Precision Floating-Point Values to
  /// Single Precision Floating-Point Values.
  | VGETEXPPS = 1047
  /// Convert Exponents of Scalar Double Precision Floating-Point Value to
  /// Double Precision Floating-Point Value.
  | VGETEXPSD = 1048
  /// Convert Exponents of Scalar FP16 Values to FP16 Values.
  | VGETEXPSH = 1049
  /// Convert Exponents of Scalar Single Precision Floating-Point Value to
  /// Single Precision Floating-Point Value.
  | VGETEXPSS = 1050
  /// Extract Float64 Vector of Normalized Mantissas From Float64 Vector.
  | VGETMANTPD = 1051
  /// Extract FP16 Vector of Normalized Mantissas from FP16 Vector.
  | VGETMANTPH = 1052
  /// Extract Float32 Vector of Normalized Mantissas From Float32 Vector.
  | VGETMANTPS = 1053
  /// Extract Float64 of Normalized Mantissa From Float64 Scalar.
  | VGETMANTSD = 1054
  /// Extract FP16 of Normalized Mantissa from FP16 Scalar.
  | VGETMANTSH = 1055
  /// Extract Float32 Vector of Normalized Mantissa From Float32 Scalar.
  | VGETMANTSS = 1056
  /// Galois Field Affine Transformation Inverse.
  | VGF2P8AFFINEINVQB = 1057
  /// Galois Field Affine Transformation.
  | VGF2P8AFFINEQB = 1058
  /// Galois Field Multiply Bytes.
  | VGF2P8MULB = 1059
  /// Packed Double Precision Floating-Point Horizontal Add.
  | VHADDPD = 1060
  /// Packed Single Precision Floating-Point Horizontal Add.
  | VHADDPS = 1061
  /// Packed Double Precision Floating-Point Horizontal Subtract.
  | VHSUBPD = 1062
  /// Packed Single Precision Floating-Point Horizontal Subtract.
  | VHSUBPS = 1063
  /// Insert Packed Floating-Point Values.
  | VINSERTF128 = 1064
  /// Insert Packed Floating-Point Values.
  | VINSERTF32X4 = 1065
  /// Insert Packed Floating-Point Values.
  | VINSERTF32X8 = 1066
  /// Insert Packed Floating-Point Values.
  | VINSERTF64X2 = 1067
  /// Insert Packed Floating-Point Values.
  | VINSERTF64X4 = 1068
  /// Insert Packed Integer Values.
  | VINSERTI128 = 1069
  /// Insert Packed Integer Values.
  | VINSERTI32X4 = 1070
  /// Insert Packed Integer Values.
  | VINSERTI32X8 = 1071
  /// Insert Packed Integer Values.
  | VINSERTI64X2 = 1072
  /// Insert Packed Integer Values.
  | VINSERTI64X4 = 1073
  /// Insert Scalar Single Precision Floating-Point Value.
  | VINSERTPS = 1074
  /// Load Unaligned Integer 128 Bits.
  | VLDDQU = 1075
  /// Load MXCSR Register.
  | VLDMXCSR = 1076
  /// Store Selected Bytes of Double Quadword.
  | VMASKMOVDQU = 1077
  /// Conditional SIMD Packed Loads and Stores.
  | VMASKMOVPD = 1078
  /// Conditional SIMD Packed Loads and Stores.
  | VMASKMOVPS = 1079
  /// Maximum of Packed Double Precision Floating-Point Values.
  | VMAXPD = 1080
  /// Return Maximum of Packed FP16 Values.
  | VMAXPH = 1081
  /// Maximum of Packed Single Precision Floating-Point Values.
  | VMAXPS = 1082
  /// Return Maximum Scalar Double Precision Floating-Point Value.
  | VMAXSD = 1083
  /// Return Maximum of Scalar FP16 Values.
  | VMAXSH = 1084
  /// Return Maximum Scalar Single Precision Floating-Point Value.
  | VMAXSS = 1085
  /// Call to VM Monitor.
  | VMCALL = 1086
  /// Clear Virtual-Machine Control Structure.
  | VMCLEAR = 1087
  /// Invoke VM function.
  | VMFUNC = 1088
  /// Minimum of Packed Double Precision Floating-Point Values.
  | VMINPD = 1089
  /// Return Minimum of Packed FP16 Values.
  | VMINPH = 1090
  /// Minimum of Packed Single Precision Floating-Point Values.
  | VMINPS = 1091
  /// Return Minimum Scalar Double Precision Floating-Point Value.
  | VMINSD = 1092
  /// Return Minimum Scalar FP16 Value.
  | VMINSH = 1093
  /// Return Minimum Scalar Single Precision Floating-Point Value.
  | VMINSS = 1094
  /// Launch Virtual Machine.
  | VMLAUNCH = 1095
  /// Move Aligned Packed Double Precision Floating-Point Values.
  | VMOVAPD = 1096
  /// Move Aligned Packed Single Precision Floating-Point Values.
  | VMOVAPS = 1097
  /// Move Doubleword/Move Quadword.
  | VMOVD = 1098
  /// Replicate Double Precision Floating-Point Values.
  | VMOVDDUP = 1099
  /// Move Aligned Packed Integer Values.
  | VMOVDQA = 1100
  /// Move Aligned Packed Integer Values.
  | VMOVDQA32 = 1101
  /// Move Aligned Packed Integer Values.
  | VMOVDQA64 = 1102
  /// Move Unaligned Packed Integer Values.
  | VMOVDQU = 1103
  /// Move Unaligned Packed Integer Values.
  | VMOVDQU16 = 1104
  /// Move Unaligned Packed Integer Values.
  | VMOVDQU32 = 1105
  /// Move Unaligned Packed Integer Values.
  | VMOVDQU64 = 1106
  /// Move Unaligned Packed Integer Values.
  | VMOVDQU8 = 1107
  /// Move Packed Single Precision Floating-Point Values High to Low.
  | VMOVHLPS = 1108
  /// Move High Packed Double Precision Floating-Point Value.
  | VMOVHPD = 1109
  /// Move High Packed Single Precision Floating-Point Values.
  | VMOVHPS = 1110
  /// Move Packed Single Precision Floating-Point Values Low to High.
  | VMOVLHPS = 1111
  /// Move Low Packed Double Precision Floating-Point Value.
  | VMOVLPD = 1112
  /// Move Low Packed Single Precision Floating-Point Values.
  | VMOVLPS = 1113
  /// Extract Packed Double Precision Floating-Point Sign Mask.
  | VMOVMSKPD = 1114
  /// Extract Packed Single Precision Floating-Point Sign Mask.
  | VMOVMSKPS = 1115
  /// Store Packed Integers Using Non-Temporal Hint.
  | VMOVNTDQ = 1116
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | VMOVNTDQA = 1117
  /// Store Packed Double Precision Floating-Point Values Using Non-Temporal
  /// Hint.
  | VMOVNTPD = 1118
  /// Store Packed Single Precision Floating-Point Values Using Non-Temporal
  /// Hint.
  | VMOVNTPS = 1119
  /// Move Doubleword/Move Quadword.
  /// Move Quadword.
  | VMOVQ = 1120
  /// Move or Merge Scalar Double Precision Floating-Point Value.
  | VMOVSD = 1121
  /// Move Scalar FP16 Value.
  | VMOVSH = 1122
  /// Replicate Single Precision Floating-Point Values.
  | VMOVSHDUP = 1123
  /// Replicate Single Precision Floating-Point Values.
  | VMOVSLDUP = 1124
  /// Move or Merge Scalar Single Precision Floating-Point Value.
  | VMOVSS = 1125
  /// Move Unaligned Packed Double Precision Floating-Point Values.
  | VMOVUPD = 1126
  /// Move Unaligned Packed Single Precision Floating-Point Values.
  | VMOVUPS = 1127
  /// Move Word.
  | VMOVW = 1128
  /// Compute Multiple Packed Sums of Absolute Difference.
  | VMPSADBW = 1129
  /// Load Pointer to Virtual-Machine Control Structure.
  | VMPTRLD = 1130
  /// Store Pointer to Virtual-Machine Control Structure.
  | VMPTRST = 1131
  /// Reads a component from the VMCS and stores it into a destination operand.
  | VMREAD = 1132
  /// Resume Virtual Machine.
  | VMRESUME = 1133
  /// Multiply Packed Double Precision Floating-Point Values.
  | VMULPD = 1134
  /// Multiply Packed FP16 Values.
  | VMULPH = 1135
  /// Multiply Packed Single Precision Floating-Point Values.
  | VMULPS = 1136
  /// Multiply Scalar Double Precision Floating-Point Value.
  | VMULSD = 1137
  /// Multiply Scalar FP16 Values.
  | VMULSH = 1138
  /// Multiply Scalar Single Precision Floating-Point Values.
  | VMULSS = 1139
  /// Leave VMX Operation.
  | VMXOFF = 1140
  /// Enter VMX Operation.
  | VMXON = 1141
  /// Bitwise Logical OR of Packed Double Precision Floating-Point Values.
  | VORPD = 1142
  /// Bitwise Logical OR of Packed Single Precision Floating-Point Values.
  | VORPS = 1143
  /// Compute Intersection Between DWORDS/QUADWORDS to a Pair of Mask Registers.
  | VP2INTERSECTD = 1144
  /// Compute Intersection Between DWORDS/QUADWORDS to a Pair of Mask Registers.
  | VP2INTERSECTQ = 1145
  /// Dot Product of Signed Words With Dword Accumulation (4-Iterations).
  | VP4DPWSSD = 1146
  /// Dot Product of Signed Words With Dword Accumulation and Saturation
  /// (4-Iterations).
  | VP4DPWSSDS = 1147
  /// Packed Absolute Value.
  | VPABSB = 1148
  /// Packed Absolute Value.
  | VPABSD = 1149
  /// Packed Absolute Value.
  | VPABSQ = 1150
  /// Packed Absolute Value.
  | VPABSW = 1151
  /// Pack With Signed Saturation.
  | VPACKSSDW = 1152
  /// Pack With Signed Saturation.
  | VPACKSSWB = 1153
  /// Pack With Unsigned Saturation.
  | VPACKUSDW = 1154
  /// Pack With Unsigned Saturation.
  | VPACKUSWB = 1155
  /// Add Packed Integers.
  | VPADDB = 1156
  /// Add Packed Integers.
  | VPADDD = 1157
  /// Add Packed Integers.
  | VPADDQ = 1158
  /// Add Packed Signed Integers with Signed Saturation.
  | VPADDSB = 1159
  /// Add Packed Signed Integers with Signed Saturation.
  | VPADDSW = 1160
  /// Add Packed Unsigned Integers With Unsigned Saturation.
  | VPADDUSB = 1161
  /// Add Packed Unsigned Integers With Unsigned Saturation.
  | VPADDUSW = 1162
  /// Add Packed Integers.
  | VPADDW = 1163
  /// Packed Align Right.
  | VPALIGNR = 1164
  /// Logical AND.
  | VPAND = 1165
  /// Logical AND.
  | VPANDD = 1166
  /// Logical AND NOT.
  | VPANDN = 1167
  /// Logical AND NOT.
  | VPANDND = 1168
  /// Logical AND NOT.
  | VPANDNQ = 1169
  /// Logical AND.
  | VPANDQ = 1170
  /// Average Packed Integers.
  | VPAVGB = 1171
  /// Average Packed Integers.
  | VPAVGW = 1172
  /// Blend Packed Dwords.
  | VPBLENDD = 1173
  /// Blend Byte/Word Vectors Using an Opmask Control.
  | VPBLENDMB = 1174
  /// Blend Int32/Int64 Vectors Using an OpMask Control.
  | VPBLENDMD = 1175
  /// Blend Int32/Int64 Vectors Using an OpMask Control.
  | VPBLENDMQ = 1176
  /// Blend Byte/Word Vectors Using an Opmask Control.
  | VPBLENDMW = 1177
  /// Variable Blend Packed Bytes.
  | VPBLENDVB = 1178
  /// Blend Packed Words.
  | VPBLENDW = 1179
  /// Load Integer and Broadcast.
  /// Load With Broadcast Integer Data From General Purpose Register.
  | VPBROADCASTB = 1180
  /// Load Integer and Broadcast.
  /// Load With Broadcast Integer Data From General Purpose Register.
  | VPBROADCASTD = 1181
  /// Broadcast Mask to Vector Register.
  | VPBROADCASTMB2Q = 1182
  /// Broadcast Mask to Vector Register.
  | VPBROADCASTMW2D = 1183
  /// Load Integer and Broadcast.
  /// Load With Broadcast Integer Data From General Purpose Register.
  | VPBROADCASTQ = 1184
  /// Load Integer and Broadcast.
  /// Load With Broadcast Integer Data From General Purpose Register.
  | VPBROADCASTW = 1185
  /// Carry-Less Multiplication Quadword.
  | VPCLMULQDQ = 1186
  /// Compare Packed Byte Values Into Mask.
  | VPCMPB = 1187
  /// Compare Packed Integer Values Into Mask.
  | VPCMPD = 1188
  /// Compare Packed Data for Equal.
  | VPCMPEQB = 1189
  /// Compare Packed Data for Equal.
  | VPCMPEQD = 1190
  /// Compare Packed Qword Data for Equal.
  | VPCMPEQQ = 1191
  /// Compare Packed Data for Equal.
  | VPCMPEQW = 1192
  /// Packed Compare Explicit Length Strings, Return Index.
  | VPCMPESTRI = 1193
  /// Packed Compare Explicit Length Strings, Return Mask.
  | VPCMPESTRM = 1194
  /// Compare Packed Signed Integers for Greater Than.
  | VPCMPGTB = 1195
  /// Compare Packed Signed Integers for Greater Than.
  | VPCMPGTD = 1196
  /// Compare Packed Data for Greater Than.
  | VPCMPGTQ = 1197
  /// Compare Packed Signed Integers for Greater Than.
  | VPCMPGTW = 1198
  /// Packed Compare Implicit Length Strings, Return Index.
  | VPCMPISTRI = 1199
  /// Packed Compare Implicit Length Strings, Return Mask.
  | VPCMPISTRM = 1200
  /// Compare Packed Integer Values Into Mask.
  | VPCMPQ = 1201
  /// Compare Packed Byte Values Into Mask.
  | VPCMPUB = 1202
  /// Compare Packed Integer Values Into Mask.
  | VPCMPUD = 1203
  /// Compare Packed Integer Values Into Mask.
  | VPCMPUQ = 1204
  /// Compare Packed Word Values Into Mask.
  | VPCMPUW = 1205
  /// Compare Packed Word Values Into Mask.
  | VPCMPW = 1206
  /// Store Sparse Packed Byte/Word Integer Values Into Dense Memory/Register.
  | VPCOMPRESSB = 1207
  /// Store Sparse Packed Doubleword Integer Values Into Dense Memory/Register.
  | VPCOMPRESSD = 1208
  /// Store Sparse Packed Quadword Integer Values Into Dense Memory/Register.
  | VPCOMPRESSQ = 1209
  /// Store Sparse Packed Byte/Word Integer Values Into Dense Memory/Register.
  | VPCOMPRESSW = 1210
  /// Detect Conflicts Within a Vector of Packed Dword/Qword Values Into Dense
  /// Memory/ Register.
  | VPCONFLICTD = 1211
  /// Detect Conflicts Within a Vector of Packed Dword/Qword Values Into Dense
  /// Memory/ Register.
  | VPCONFLICTQ = 1212
  /// Multiply and Add Unsigned and Signed Bytes With and Without Saturation.
  | VPDPBSSD = 1213
  /// Multiply and Add Unsigned and Signed Bytes With and Without Saturation.
  | VPDPBSSDS = 1214
  /// Multiply and Add Unsigned and Signed Bytes With and Without Saturation.
  | VPDPBSUD = 1215
  /// Multiply and Add Unsigned and Signed Bytes With and Without Saturation.
  | VPDPBSUDS = 1216
  /// Multiply and Add Unsigned and Signed Bytes.
  | VPDPBUSD = 1217
  /// Multiply and Add Unsigned and Signed Bytes With Saturation.
  | VPDPBUSDS = 1218
  /// Multiply and Add Unsigned and Signed Bytes With and Without Saturation.
  | VPDPBUUD = 1219
  /// Multiply and Add Unsigned and Signed Bytes With and Without Saturation.
  | VPDPBUUDS = 1220
  /// Multiply and Add Signed Word Integers.
  | VPDPWSSD = 1221
  /// Multiply and Add Signed Word Integers With Saturation.
  | VPDPWSSDS = 1222
  /// Multiply and Add Unsigned and Signed Words With and Without Saturation.
  | VPDPWSUD = 1223
  /// Multiply and Add Unsigned and Signed Words With and Without Saturation.
  | VPDPWSUDS = 1224
  /// Multiply and Add Unsigned and Signed Words With and Without Saturation.
  | VPDPWUSD = 1225
  /// Multiply and Add Unsigned and Signed Words With and Without Saturation.
  | VPDPWUSDS = 1226
  /// Multiply and Add Unsigned and Signed Words With and Without Saturation.
  | VPDPWUUD = 1227
  /// Multiply and Add Unsigned and Signed Words With and Without Saturation.
  | VPDPWUUDS = 1228
  /// Permute Floating-Point Values.
  | VPERM2F128 = 1229
  /// Permute Integer Values.
  | VPERM2I128 = 1230
  /// Permute Packed Bytes Elements.
  | VPERMB = 1231
  /// Permute Packed Doubleword/Word Elements.
  | VPERMD = 1232
  /// Full Permute of Bytes From Two Tables Overwriting the Index.
  | VPERMI2B = 1233
  /// Full Permute From Two Tables Overwriting the Index.
  | VPERMI2D = 1234
  /// Full Permute From Two Tables Overwriting the Index.
  | VPERMI2PD = 1235
  /// Full Permute From Two Tables Overwriting the Index.
  | VPERMI2PS = 1236
  /// Full Permute From Two Tables Overwriting the Index.
  | VPERMI2Q = 1237
  /// Full Permute From Two Tables Overwriting the Index.
  | VPERMI2W = 1238
  /// Permute In-Lane of Pairs of Double Precision Floating-Point Values.
  | VPERMILPD = 1239
  /// Permute In-Lane of Quadruples of Single Precision Floating-Point Values.
  | VPERMILPS = 1240
  /// Permute Double Precision Floating-Point Elements.
  | VPERMPD = 1241
  /// Permute Single Precision Floating-Point Elements.
  | VPERMPS = 1242
  /// Qwords Element Permutation.
  | VPERMQ = 1243
  /// Full Permute of Bytes From Two Tables Overwriting a Table.
  | VPERMT2B = 1244
  /// Full Permute From Two Tables Overwriting One Table.
  | VPERMT2D = 1245
  /// Full Permute From Two Tables Overwriting One Table.
  | VPERMT2PD = 1246
  /// Full Permute From Two Tables Overwriting One Table.
  | VPERMT2PS = 1247
  /// Full Permute From Two Tables Overwriting One Table.
  | VPERMT2Q = 1248
  /// Full Permute From Two Tables Overwriting One Table.
  | VPERMT2W = 1249
  /// Permute Packed Doubleword/Word Elements.
  | VPERMW = 1250
  /// Expand Byte/Word Values.
  | VPEXPANDB = 1251
  /// Load Sparse Packed Doubleword Integer Values From Dense Memory/Register.
  | VPEXPANDD = 1252
  /// Load Sparse Packed Quadword Integer Values From Dense Memory/Register.
  | VPEXPANDQ = 1253
  /// Expand Byte/Word Values.
  | VPEXPANDW = 1254
  /// Extract Byte/Dword/Qword.
  | VPEXTRB = 1255
  /// Extract Byte/Dword/Qword.
  | VPEXTRD = 1256
  /// Extract Byte/Dword/Qword.
  | VPEXTRQ = 1257
  /// Extract Word.
  | VPEXTRW = 1258
  /// Gather Packed Dword, Packed Qword With Signed Dword Indices.
  /// Gather Packed Dword Values Using Signed Dword/Qword Indices.
  | VPGATHERDD = 1259
  /// Gather Packed Dword, Packed Qword With Signed Dword Indices.
  /// Gather Packed Qword Values Using Signed Dword/Qword Indices.
  | VPGATHERDQ = 1260
  /// Gather Packed Dword Values Using Signed Dword/Qword Indices.
  /// Gather Packed Dword, Packed Qword with Signed Qword Indices.
  | VPGATHERQD = 1261
  /// Gather Packed Qword Values Using Signed Dword/Qword Indices.
  /// Gather Packed Dword, Packed Qword with Signed Qword Indices.
  | VPGATHERQQ = 1262
  /// Packed Horizontal Add.
  | VPHADDD = 1263
  /// Packed Horizontal Add and Saturate.
  | VPHADDSW = 1264
  /// Packed Horizontal Add.
  | VPHADDW = 1265
  /// Packed Horizontal Word Minimum.
  | VPHMINPOSUW = 1266
  /// Packed Horizontal Subtract.
  | VPHSUBD = 1267
  /// Packed Horizontal Subtract and Saturate.
  | VPHSUBSW = 1268
  /// Packed Horizontal Subtract.
  | VPHSUBW = 1269
  /// Insert Byte/Dword/Qword.
  | VPINSRB = 1270
  /// Insert Byte/Dword/Qword.
  | VPINSRD = 1271
  /// Insert Byte/Dword/Qword.
  | VPINSRQ = 1272
  /// Insert Word.
  | VPINSRW = 1273
  /// Count the Number of Leading Zero Bits for Packed Dword, Packed Qword
  /// Values.
  | VPLZCNTD = 1274
  /// Count the Number of Leading Zero Bits for Packed Dword, Packed Qword
  /// Values.
  | VPLZCNTQ = 1275
  /// Packed Multiply of Unsigned 52-Bit Unsigned Integers and Add High 52-Bit
  /// Products to 64-Bit Accumulators.
  | VPMADD52HUQ = 1276
  /// Packed Multiply of Unsigned 52-Bit Integers and Add the Low 52-Bit
  /// Products to Qword Accumulators.
  | VPMADD52LUQ = 1277
  /// Multiply and Add Packed Signed and Unsigned Bytes.
  | VPMADDUBSW = 1278
  /// Multiply and Add Packed Integers.
  | VPMADDWD = 1279
  /// Conditional SIMD Integer Packed Loads and Stores.
  | VPMASKMOVD = 1280
  /// Conditional SIMD Integer Packed Loads and Stores.
  | VPMASKMOVQ = 1281
  /// Maximum of Packed Signed Integers.
  | VPMAXSB = 1282
  /// Maximum of Packed Signed Integers.
  | VPMAXSD = 1283
  /// Maximum of Packed Signed Integers.
  | VPMAXSQ = 1284
  /// Maximum of Packed Signed Integers.
  | VPMAXSW = 1285
  /// Maximum of Packed Unsigned Integers.
  | VPMAXUB = 1286
  /// Maximum of Packed Unsigned Integers.
  | VPMAXUD = 1287
  /// Maximum of Packed Unsigned Integers.
  | VPMAXUQ = 1288
  /// Maximum of Packed Unsigned Integers.
  | VPMAXUW = 1289
  /// Minimum of Packed Signed Integers.
  | VPMINSB = 1290
  /// Minimum of Packed Signed Integers.
  | VPMINSD = 1291
  /// Minimum of Packed Signed Integers.
  | VPMINSQ = 1292
  /// Minimum of Packed Signed Integers.
  | VPMINSW = 1293
  /// Minimum of Packed Unsigned Integers.
  | VPMINUB = 1294
  /// Minimum of Packed Unsigned Integers.
  | VPMINUD = 1295
  /// Minimum of Packed Unsigned Integers.
  | VPMINUQ = 1296
  /// Minimum of Packed Unsigned Integers.
  | VPMINUW = 1297
  /// Convert a Vector Register to a Mask.
  | VPMOVB2M = 1298
  /// Convert a Vector Register to a Mask.
  | VPMOVD2M = 1299
  /// Down Convert DWord to Byte.
  | VPMOVDB = 1300
  /// Down Convert DWord to Word.
  | VPMOVDW = 1301
  /// Convert a Mask Register to a Vector Register.
  | VPMOVM2B = 1302
  /// Convert a Mask Register to a Vector Register.
  | VPMOVM2D = 1303
  /// Convert a Mask Register to a Vector Register.
  | VPMOVM2Q = 1304
  /// Convert a Mask Register to a Vector Register.
  | VPMOVM2W = 1305
  /// Move Byte Mask.
  | VPMOVMSKB = 1306
  /// Convert a Vector Register to a Mask.
  | VPMOVQ2M = 1307
  /// Down Convert QWord to Byte.
  | VPMOVQB = 1308
  /// Down Convert QWord to DWord.
  | VPMOVQD = 1309
  /// Down Convert QWord to Word.
  | VPMOVQW = 1310
  /// Down Convert DWord to Byte.
  | VPMOVSDB = 1311
  /// Down Convert DWord to Word.
  | VPMOVSDW = 1312
  /// Down Convert QWord to Byte.
  | VPMOVSQB = 1313
  /// Down Convert QWord to DWord.
  | VPMOVSQD = 1314
  /// Down Convert QWord to Word.
  | VPMOVSQW = 1315
  /// Down Convert Word to Byte.
  | VPMOVSWB = 1316
  /// Packed Move With Sign Extend.
  | VPMOVSXBD = 1317
  /// Packed Move With Sign Extend.
  | VPMOVSXBQ = 1318
  /// Packed Move With Sign Extend.
  | VPMOVSXBW = 1319
  /// Packed Move With Sign Extend.
  | VPMOVSXDQ = 1320
  /// Packed Move With Sign Extend.
  | VPMOVSXWD = 1321
  /// Packed Move With Sign Extend.
  | VPMOVSXWQ = 1322
  /// Down Convert DWord to Byte.
  | VPMOVUSDB = 1323
  /// Down Convert DWord to Word.
  | VPMOVUSDW = 1324
  /// Down Convert QWord to Byte.
  | VPMOVUSQB = 1325
  /// Down Convert QWord to DWord.
  | VPMOVUSQD = 1326
  /// Down Convert QWord to Word.
  | VPMOVUSQW = 1327
  /// Down Convert Word to Byte.
  | VPMOVUSWB = 1328
  /// Convert a Vector Register to a Mask.
  | VPMOVW2M = 1329
  /// Down Convert Word to Byte.
  | VPMOVWB = 1330
  /// Packed Move With Zero Extend.
  | VPMOVZXBD = 1331
  /// Packed Move With Zero Extend.
  | VPMOVZXBQ = 1332
  /// Packed Move With Zero Extend.
  | VPMOVZXBW = 1333
  /// Packed Move With Zero Extend.
  | VPMOVZXDQ = 1334
  /// Packed Move With Zero Extend.
  | VPMOVZXWD = 1335
  /// Packed Move With Zero Extend.
  | VPMOVZXWQ = 1336
  /// Multiply Packed Doubleword Integers.
  | VPMULDQ = 1337
  /// Packed Multiply High With Round and Scale.
  | VPMULHRSW = 1338
  /// Multiply Packed Unsigned Integers and Store High Result.
  | VPMULHUW = 1339
  /// Multiply Packed Signed Integers and Store High Result.
  | VPMULHW = 1340
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLD = 1341
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLQ = 1342
  /// Multiply Packed Signed Integers and Store Low Result.
  | VPMULLW = 1343
  /// Select Packed Unaligned Bytes From Quadword Sources.
  | VPMULTISHIFTQB = 1344
  /// Multiply Packed Unsigned Doubleword Integers.
  | VPMULUDQ = 1345
  /// Return the Count of Number of Bits Set to 1 in BYTE/WORD/DWORD/QWORD.
  | VPOPCNTB = 1346
  /// Return the Count of Number of Bits Set to 1 in BYTE/WORD/DWORD/QWORD.
  | VPOPCNTD = 1347
  /// Return the Count of Number of Bits Set to 1 in BYTE/WORD/DWORD/QWORD.
  | VPOPCNTQ = 1348
  /// Return the Count of Number of Bits Set to 1 in BYTE/WORD/DWORD/QWORD.
  | VPOPCNTW = 1349
  /// Bitwise Logical OR.
  | VPOR = 1350
  /// Bitwise Logical OR.
  | VPORD = 1351
  /// Bitwise Logical OR.
  | VPORQ = 1352
  /// Bit Rotate Left.
  | VPROLD = 1353
  /// Bit Rotate Left.
  | VPROLQ = 1354
  /// Bit Rotate Left.
  | VPROLVD = 1355
  /// Bit Rotate Left.
  | VPROLVQ = 1356
  /// Bit Rotate Right.
  | VPRORD = 1357
  /// Bit Rotate Right.
  | VPRORQ = 1358
  /// Bit Rotate Right.
  | VPRORVD = 1359
  /// Bit Rotate Right.
  | VPRORVQ = 1360
  /// Compute Sum of Absolute Differences.
  | VPSADBW = 1361
  /// Scatter Packed Dword, Packed Qword with Signed Dword, Signed Qword
  /// Indices.
  | VPSCATTERDD = 1362
  /// Scatter Packed Dword, Packed Qword with Signed Dword, Signed Qword
  /// Indices.
  | VPSCATTERDQ = 1363
  /// Scatter Packed Dword, Packed Qword with Signed Dword, Signed Qword
  /// Indices.
  | VPSCATTERQD = 1364
  /// Scatter Packed Dword, Packed Qword with Signed Dword, Signed Qword
  /// Indices.
  | VPSCATTERQQ = 1365
  /// Concatenate and Shift Packed Data Left Logical.
  | VPSHLDD = 1366
  /// Concatenate and Shift Packed Data Left Logical.
  | VPSHLDQ = 1367
  /// Concatenate and Variable Shift Packed Data Left Logical.
  | VPSHLDVD = 1368
  /// Concatenate and Variable Shift Packed Data Left Logical.
  | VPSHLDVQ = 1369
  /// Concatenate and Variable Shift Packed Data Left Logical.
  | VPSHLDVW = 1370
  /// Concatenate and Shift Packed Data Left Logical.
  | VPSHLDW = 1371
  /// Concatenate and Shift Packed Data Right Logical.
  | VPSHRDD = 1372
  /// Concatenate and Shift Packed Data Right Logical.
  | VPSHRDQ = 1373
  /// Concatenate and Variable Shift Packed Data Right Logical.
  | VPSHRDVD = 1374
  /// Concatenate and Variable Shift Packed Data Right Logical.
  | VPSHRDVQ = 1375
  /// Concatenate and Variable Shift Packed Data Right Logical.
  | VPSHRDVW = 1376
  /// Concatenate and Shift Packed Data Right Logical.
  | VPSHRDW = 1377
  /// Packed Shuffle Bytes.
  | VPSHUFB = 1378
  /// Shuffle Bits From Quadword Elements Using Byte Indexes Into Mask.
  | VPSHUFBITQMB = 1379
  /// Shuffle Packed Doublewords.
  | VPSHUFD = 1380
  /// Shuffle Packed High Words.
  | VPSHUFHW = 1381
  /// Shuffle Packed Low Words.
  | VPSHUFLW = 1382
  /// Packed SIGN.
  | VPSIGNB = 1383
  /// Packed SIGN.
  | VPSIGND = 1384
  /// Packed SIGN.
  | VPSIGNW = 1385
  /// Shift Packed Data Left Logical.
  | VPSLLD = 1386
  /// Shift Double Quadword Left Logical.
  | VPSLLDQ = 1387
  /// Shift Packed Data Left Logical.
  | VPSLLQ = 1388
  /// Variable Bit Shift Left Logical.
  | VPSLLVD = 1389
  /// Variable Bit Shift Left Logical.
  | VPSLLVQ = 1390
  /// Variable Bit Shift Left Logical.
  | VPSLLVW = 1391
  /// Shift Packed Data Left Logical.
  | VPSLLW = 1392
  /// Shift Packed Data Right Arithmetic.
  | VPSRAD = 1393
  /// Shift Packed Data Right Arithmetic.
  | VPSRAQ = 1394
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVD = 1395
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVQ = 1396
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVW = 1397
  /// Shift Packed Data Right Arithmetic.
  | VPSRAW = 1398
  /// Shift Packed Data Right Logical.
  | VPSRLD = 1399
  /// Shift Double Quadword Right Logical.
  | VPSRLDQ = 1400
  /// Shift Packed Data Right Logical.
  | VPSRLQ = 1401
  /// Variable Bit Shift Right Logical.
  | VPSRLVD = 1402
  /// Variable Bit Shift Right Logical.
  | VPSRLVQ = 1403
  /// Variable Bit Shift Right Logical.
  | VPSRLVW = 1404
  /// Shift Packed Data Right Logical.
  | VPSRLW = 1405
  /// Subtract Packed Integers.
  | VPSUBB = 1406
  /// Subtract Packed Integers.
  | VPSUBD = 1407
  /// Subtract Packed Quadword Integers.
  | VPSUBQ = 1408
  /// Subtract Packed Signed Integers With Signed Saturation.
  | VPSUBSB = 1409
  /// Subtract Packed Signed Integers With Signed Saturation.
  | VPSUBSW = 1410
  /// Subtract Packed Unsigned Integers With Unsigned Saturation.
  | VPSUBUSB = 1411
  /// Subtract Packed Unsigned Integers With Unsigned Saturation.
  | VPSUBUSW = 1412
  /// Subtract Packed Integers.
  | VPSUBW = 1413
  /// Bitwise Ternary Logic.
  | VPTERNLOGD = 1414
  /// Bitwise Ternary Logic.
  | VPTERNLOGQ = 1415
  /// Logical Compare.
  | VPTEST = 1416
  /// Logical AND and Set Mask.
  | VPTESTMB = 1417
  /// Logical AND and Set Mask.
  | VPTESTMD = 1418
  /// Logical AND and Set Mask.
  | VPTESTMQ = 1419
  /// Logical AND and Set Mask.
  | VPTESTMW = 1420
  /// Logical NAND and Set.
  | VPTESTNMB = 1421
  /// Logical NAND and Set.
  | VPTESTNMD = 1422
  /// Logical NAND and Set.
  | VPTESTNMQ = 1423
  /// Logical NAND and Set.
  | VPTESTNMW = 1424
  /// Unpack High Data.
  | VPUNPCKHBW = 1425
  /// Unpack High Data.
  | VPUNPCKHDQ = 1426
  /// Unpack High Data.
  | VPUNPCKHQDQ = 1427
  /// Unpack High Data.
  | VPUNPCKHWD = 1428
  /// Unpack Low Data.
  | VPUNPCKLBW = 1429
  /// Unpack Low Data.
  | VPUNPCKLDQ = 1430
  /// Unpack Low Data.
  | VPUNPCKLQDQ = 1431
  /// Unpack Low Data.
  | VPUNPCKLWD = 1432
  /// Logical Exclusive OR.
  | VPXOR = 1433
  /// Logical Exclusive OR.
  | VPXORD = 1434
  /// Logical Exclusive OR.
  | VPXORQ = 1435
  /// Range Restriction Calculation for Packed Pairs of Float64 Values.
  | VRANGEPD = 1436
  /// Range Restriction Calculation for Packed Pairs of Float32 Values.
  | VRANGEPS = 1437
  /// Range Restriction Calculation From a Pair of Scalar Float64 Values.
  | VRANGESD = 1438
  /// Range Restriction Calculation From a Pair of Scalar Float32 Values.
  | VRANGESS = 1439
  /// Compute Approximate Reciprocals of Packed Float64 Values.
  | VRCP14PD = 1440
  /// Compute Approximate Reciprocals of Packed Float32 Values.
  | VRCP14PS = 1441
  /// Compute Approximate Reciprocal of Scalar Float64 Value.
  | VRCP14SD = 1442
  /// Compute Approximate Reciprocal of Scalar Float32 Value.
  | VRCP14SS = 1443
  /// Approximation to the Reciprocal of Packed Double Precision Floating-Point
  /// Values With Less Than 2^-28 Relative Error.
  | VRCP28PD = 1444
  /// Approximation to the Reciprocal of Packed Single Precision Floating-Point
  /// Values With Less Than 2^-28 Relative Error.
  | VRCP28PS = 1445
  /// Approximation to the Reciprocal of Scalar Double Precision Floating-Point
  /// Value With Less Than 2^-28 Relative Error.
  | VRCP28SD = 1446
  /// Approximation to the Reciprocal of Scalar Single Precision Floating-Point
  /// Value With Less Than 2^-28 Relative Error.
  | VRCP28SS = 1447
  /// Compute Reciprocals of Packed FP16 Values.
  | VRCPPH = 1448
  /// Compute Reciprocals of Packed Single Precision Floating-Point Values.
  | VRCPPS = 1449
  /// Compute Reciprocal of Scalar FP16 Value.
  | VRCPSH = 1450
  /// Compute Reciprocal of Scalar Single Precision Floating-Point Values.
  | VRCPSS = 1451
  /// Perform Reduction Transformation on Packed Float64 Values.
  | VREDUCEPD = 1452
  /// Perform Reduction Transformation on Packed FP16 Values.
  | VREDUCEPH = 1453
  /// Perform Reduction Transformation on Packed Float32 Values.
  | VREDUCEPS = 1454
  /// Perform a Reduction Transformation on a Scalar Float64 Value.
  | VREDUCESD = 1455
  /// Perform Reduction Transformation on Scalar FP16 Value.
  | VREDUCESH = 1456
  /// Perform a Reduction Transformation on a Scalar Float32 Value.
  | VREDUCESS = 1457
  /// Round Packed Float64 Values to Include a Given Number of Fraction Bits.
  | VRNDSCALEPD = 1458
  /// Round Packed FP16 Values to Include a Given Number of Fraction Bits.
  | VRNDSCALEPH = 1459
  /// Round Packed Float32 Values to Include a Given Number of Fraction Bits.
  | VRNDSCALEPS = 1460
  /// Round Scalar Float64 Value to Include a Given Number of Fraction Bits.
  | VRNDSCALESD = 1461
  /// Round Scalar FP16 Value to Include a Given Number of Fraction Bits.
  | VRNDSCALESH = 1462
  /// Round Scalar Float32 Value to Include a Given Number of Fraction Bits.
  | VRNDSCALESS = 1463
  /// Round Packed Double Precision Floating-Point Values.
  | VROUNDPD = 1464
  /// Round Packed Single Precision Floating-Point Values.
  | VROUNDPS = 1465
  /// Round Scalar Double Precision Floating-Point Values.
  | VROUNDSD = 1466
  /// Round Scalar Single Precision Floating-Point Values.
  | VROUNDSS = 1467
  /// Compute Approximate Reciprocals of Square Roots of Packed Float64 Values.
  | VRSQRT14PD = 1468
  /// Compute Approximate Reciprocals of Square Roots of Packed Float32 Values.
  | VRSQRT14PS = 1469
  /// Compute Approximate Reciprocal of Square Root of Scalar Float64 Value.
  | VRSQRT14SD = 1470
  /// Compute Approximate Reciprocal of Square Root of Scalar Float32 Value.
  | VRSQRT14SS = 1471
  /// Approximation to the Reciprocal Square Root of Packed Double Precision
  /// Floating-Point Values With Less Than 2^-28 Relative Error.
  | VRSQRT28PD = 1472
  /// Approximation to the Reciprocal Square Root of Packed Single Precision
  /// Floating-Point Values With Less Than 2^-28 Relative Error.
  | VRSQRT28PS = 1473
  /// Approximation to the Reciprocal Square Root of Scalar Double Precision
  /// Floating-Point Value With Less Than 2^-28 Relative Error.
  | VRSQRT28SD = 1474
  /// Approximation to the Reciprocal Square Root of Scalar Single Precision
  /// Floating-Point Value With Less Than 2^-28 Relative Error.
  | VRSQRT28SS = 1475
  /// Compute Reciprocals of Square Roots of Packed FP16 Values.
  | VRSQRTPH = 1476
  /// Compute Reciprocals of Square Roots of Packed Single Precision
  /// Floating-Point Values.
  | VRSQRTPS = 1477
  /// Compute Approximate Reciprocal of Square Root of Scalar FP16 Value.
  | VRSQRTSH = 1478
  /// Compute Reciprocal of Square Root of Scalar Single Precision
  /// Floating-Point Value.
  | VRSQRTSS = 1479
  /// Scale Packed Float64 Values With Float64 Values.
  | VSCALEFPD = 1480
  /// Scale Packed FP16 Values with FP16 Values.
  | VSCALEFPH = 1481
  /// Scale Packed Float32 Values With Float32 Values.
  | VSCALEFPS = 1482
  /// Scale Scalar Float64 Values With Float64 Values.
  | VSCALEFSD = 1483
  /// Scale Scalar FP16 Values with FP16 Values.
  | VSCALEFSH = 1484
  /// Scale Scalar Float32 Value With Float32 Value.
  | VSCALEFSS = 1485
  /// Scatter Packed Single Precision, Packed Double Precision Floating-Point
  /// Values with Signed Dword and Qword Indices.
  | VSCATTERDPD = 1486
  /// Scatter Packed Single Precision, Packed Double Precision Floating-Point
  /// Values with Signed Dword and Qword Indices.
  | VSCATTERDPS = 1487
  /// Sparse Prefetch Packed SP/DP Data Values with Signed Dword, Signed Qword
  /// Indices Using T0 Hint With Intent to Write.
  | VSCATTERPF0DPD = 1488
  /// Sparse Prefetch Packed SP/DP Data Values with Signed Dword, Signed Qword
  /// Indices Using T0 Hint With Intent to Write.
  | VSCATTERPF0DPS = 1489
  /// Sparse Prefetch Packed SP/DP Data Values with Signed Dword, Signed Qword
  /// Indices Using T0 Hint With Intent to Write.
  | VSCATTERPF0QPD = 1490
  /// Sparse Prefetch Packed SP/DP Data Values with Signed Dword, Signed Qword
  /// Indices Using T0 Hint With Intent to Write.
  | VSCATTERPF0QPS = 1491
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T1 Hint With Intent to Write.
  | VSCATTERPF1DPD = 1492
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T1 Hint With Intent to Write.
  | VSCATTERPF1DPS = 1493
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T1 Hint With Intent to Write.
  | VSCATTERPF1QPD = 1494
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T1 Hint With Intent to Write.
  | VSCATTERPF1QPS = 1495
  /// Scatter Packed Single Precision, Packed Double Precision Floating-Point
  /// Values with Signed Dword and Qword Indices.
  | VSCATTERQPD = 1496
  /// Scatter Packed Single Precision, Packed Double Precision Floating-Point
  /// Values with Signed Dword and Qword Indices.
  | VSCATTERQPS = 1497
  /// Perform an Intermediate Calculation for the Next Four SHA512 Message
  /// Qwords.
  | VSHA512MSG1 = 1498
  /// Perform a Final Calculation for the Next Four SHA512 Message Qwords.
  | VSHA512MSG2 = 1499
  /// Perform Two Rounds of SHA512 Operation.
  | VSHA512RNDS2 = 1500
  /// Shuffle Packed Values at 128-Bit Granularity.
  | VSHUFF32X4 = 1501
  /// Shuffle Packed Values at 128-Bit Granularity.
  | VSHUFF64X2 = 1502
  /// Shuffle Packed Values at 128-Bit Granularity.
  | VSHUFI32X4 = 1503
  /// Shuffle Packed Values at 128-Bit Granularity.
  | VSHUFI64X2 = 1504
  /// Packed Interleave Shuffle of Pairs of Double Precision Floating-Point
  /// Values.
  | VSHUFPD = 1505
  /// Packed Interleave Shuffle of Quadruplets of Single Precision
  /// Floating-Point Values.
  | VSHUFPS = 1506
  /// Perform Initial Calculation for the Next Four SM3 Message Words.
  | VSM3MSG1 = 1507
  /// Perform Final Calculation for the Next Four SM3 Message Words.
  | VSM3MSG2 = 1508
  /// Perform Two Rounds of SM3 Operation.
  | VSM3RNDS2 = 1509
  /// Perform Four Rounds of SM4 Key Expansion.
  | VSM4KEY4 = 1510
  /// Performs Four Rounds of SM4 Encryption.
  | VSM4RNDS4 = 1511
  /// Square Root of Double Precision Floating-Point Values.
  | VSQRTPD = 1512
  /// Compute Square Root of Packed FP16 Values.
  | VSQRTPH = 1513
  /// Square Root of Single Precision Floating-Point Values.
  | VSQRTPS = 1514
  /// Compute Square Root of Scalar Double Precision Floating-Point Value.
  | VSQRTSD = 1515
  /// Compute Square Root of Scalar FP16 Value.
  | VSQRTSH = 1516
  /// Compute Square Root of Scalar Single Precision Value.
  | VSQRTSS = 1517
  /// Store MXCSR Register State.
  | VSTMXCSR = 1518
  /// Subtract Packed Double Precision Floating-Point Values.
  | VSUBPD = 1519
  /// Subtract Packed FP16 Values.
  | VSUBPH = 1520
  /// Subtract Packed Single Precision Floating-Point Values.
  | VSUBPS = 1521
  /// Subtract Scalar Double Precision Floating-Point Value.
  | VSUBSD = 1522
  /// Subtract Scalar FP16 Value.
  | VSUBSH = 1523
  /// Subtract Scalar Single Precision Floating-Point Value.
  | VSUBSS = 1524
  /// Packed Bit Test.
  | VTESTPD = 1525
  /// Packed Bit Test.
  | VTESTPS = 1526
  /// Unordered Compare Scalar Double Precision Floating-Point Values and Set
  /// EFLAGS.
  | VUCOMISD = 1527
  /// Unordered Compare Scalar FP16 Values and Set EFLAGS.
  | VUCOMISH = 1528
  /// Unordered Compare Scalar Single Precision Floating-Point Values and Set
  /// EFLAGS.
  | VUCOMISS = 1529
  /// Unpack and Interleave High Packed Double Precision Floating-Point Values.
  | VUNPCKHPD = 1530
  /// Unpack and Interleave High Packed Single Precision Floating-Point Values.
  | VUNPCKHPS = 1531
  /// Unpack and Interleave Low Packed Double Precision Floating-Point Values.
  | VUNPCKLPD = 1532
  /// Unpack and Interleave Low Packed Single Precision Floating-Point Values.
  | VUNPCKLPS = 1533
  /// Bitwise Logical XOR of Packed Double Precision Floating-Point Values.
  | VXORPD = 1534
  /// Bitwise Logical XOR of Packed Single Precision Floating-Point Values.
  | VXORPS = 1535
  /// Zero XMM, YMM, and ZMM Registers.
  | VZEROALL = 1536
  /// Zero Upper Bits of YMM and ZMM Registers.
  | VZEROUPPER = 1537
  /// Wait.
  | WAIT = 1538
  /// Write Back and Invalidate Cache.
  | WBINVD = 1539
  /// Write Back and Do Not Invalidate Cache.
  | WBNOINVD = 1540
  /// Write FS/GS Segment Base.
  | WRFSBASE = 1541
  /// Write FS/GS Segment Base.
  | WRGSBASE = 1542
  /// Write to Model Specific Register.
  | WRMSR = 1543
  /// Write List of Model Specific Registers.
  | WRMSRLIST = 1544
  /// Non-Serializing Write to Model Specific Register.
  | WRMSRNS = 1545
  /// Write Data to User Page Key Register.
  | WRPKRU = 1546
  /// Write to Shadow Stack.
  | WRSSD = 1547
  /// Write to Shadow Stack.
  | WRSSQ = 1548
  /// Write to User Shadow Stack.
  | WRUSSD = 1549
  /// Write to User Shadow Stack.
  | WRUSSQ = 1550
  /// Transactional Abort.
  | XABORT = 1551
  /// Hardware Lock Elision Prefix Hints.
  | XACQUIRE = 1552
  /// Exchange and Add.
  | XADD = 1553
  /// Transactional Begin.
  | XBEGIN = 1554
  /// Exchange Register/Memory With Register.
  | XCHG = 1555
  /// Cipher Block Chaining.
  | XCRYPTCBC = 1556
  /// Cipher Feedback Mode.
  | XCRYPTCFB = 1557
  /// Counter Mode (ACE2).
  | XCRYPTCTR = 1558
  /// Electronic code book.
  | XCRYPTECB = 1559
  /// Output Feedback Mode.
  | XCRYPTOFB = 1560
  /// Transactional End.
  | XEND = 1561
  /// Get Value of Extended Control Register.
  | XGETBV = 1562
  /// Table Look-up Translation.
  | XLAT = 1563
  /// Table Look-up Translation.
  | XLATB = 1564
  /// Modular Multiplication.
  | XMODEXP = 1565
  /// Logical Exclusive OR.
  | XOR = 1566
  /// Bitwise Logical XOR of Packed Double Precision Floating-Point Values.
  | XORPD = 1567
  /// Bitwise Logical XOR of Packed Single Precision Floating-Point Values.
  | XORPS = 1568
  /// Hardware Lock Elision Prefix Hints.
  | XRELEASE = 1569
  /// Resume Tracking Load Addresses.
  | XRESLDTRK = 1570
  /// Random Number Generation.
  | XRNG2 = 1571
  /// Restore Processor Extended States.
  | XRSTOR = 1572
  /// Restore Processor Extended States.
  | XRSTOR64 = 1573
  /// Restore Processor Extended States Supervisor.
  | XRSTORS = 1574
  /// Restore Processor Extended States Supervisor.
  | XRSTORS64 = 1575
  /// Save Processor Extended States.
  | XSAVE = 1576
  /// Save Processor Extended States.
  | XSAVE64 = 1577
  /// Save Processor Extended States With Compaction.
  | XSAVEC = 1578
  /// Save Processor Extended States With Compaction.
  | XSAVEC64 = 1579
  /// Save Processor Extended States Optimized.
  | XSAVEOPT = 1580
  /// Save Processor Extended States Optimized.
  | XSAVEOPT64 = 1581
  /// Save Processor Extended States Supervisor.
  | XSAVES = 1582
  /// Save Processor Extended States Supervisor.
  | XSAVES64 = 1583
  /// Set Extended Control Register.
  | XSETBV = 1584
  /// Hash Function SHA-1.
  | XSHA1 = 1585
  /// Hash Function SHA-256.
  | XSHA256 = 1586
  /// Hash Function SHA-384.
  | XSHA384 = 1587
  /// Hash Function SHA-512.
  | XSHA512 = 1588
  /// Store Available Random Bytes.
  | XSTORERNG = 1589
  /// Suspend Tracking Load Addresses.
  | XSUSLDTRK = 1590
  /// Test if in Transactional Execution.
  | XTEST = 1591
  /// Invalid Opcode.
  | InvalOP = 1592

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
    | Opcode.WRUSSD | Opcode.WRUSSQ | Opcode.SETSSBSY | Opcode.CLRSSBSY -> true
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
    | Opcode.CMOVB -> "cmovb"
    | Opcode.CMOVBE -> "cmovbe"
    | Opcode.CMOVG -> "cmovg"
    | Opcode.CMOVL -> "cmovl"
    | Opcode.CMOVLE -> "cmovle"
    | Opcode.CMOVNB -> "cmovnb"
    | Opcode.CMOVNL -> "cmovnl"
    | Opcode.CMOVNO -> "cmovno"
    | Opcode.CMOVNP -> "cmovnp"
    | Opcode.CMOVNS -> "cmovns"
    | Opcode.CMOVNZ -> "cmovnz"
    | Opcode.CMOVO -> "cmovo"
    | Opcode.CMOVP -> "cmovp"
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
    | Opcode.SETB -> "setb"
    | Opcode.SETBE -> "setbe"
    | Opcode.SETG -> "setg"
    | Opcode.SETL -> "setl"
    | Opcode.SETLE -> "setle"
    | Opcode.SETNB -> "setnb"
    | Opcode.SETNL -> "setnl"
    | Opcode.SETNO -> "setno"
    | Opcode.SETNP -> "setnp"
    | Opcode.SETNS -> "setns"
    | Opcode.SETNZ -> "setnz"
    | Opcode.SETO -> "seto"
    | Opcode.SETP -> "setp"
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
