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
/// Represents an Intel opcode. This type should be generated using
/// <c>scripts/genOpcode.fsx</c> from the `IntelSupportedOpcodes.txt` file.
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
  /// Add with Carry.
  | ADC = 4
  /// Unsigned integer add with carry.
  | ADCX = 5
  /// Add.
  | ADD = 6
  /// Add Packed Double-Precision Floating-Point Values.
  | ADDPD = 7
  /// Add Packed Single-Precision Floating-Point Values.
  | ADDPS = 8
  /// Add Scalar Double-Precision Floating-Point Values.
  | ADDSD = 9
  /// Add Scalar Single-Precision Floating-Point Values.
  | ADDSS = 10
  /// Packed Double-FP Add/Subtract.
  | ADDSUBPD = 11
  /// Packed Single-FP Add/Subtract.
  | ADDSUBPS = 12
  /// Unsigned integer add with overflow.
  | ADOX = 13
  /// Perform an AES decryption round using an 128-bit state and a round key.
  | AESDEC = 14
  /// Perform Last Round of an AES Decryption Flow.
  | AESDECLAST = 15
  /// Perform an AES encryption round using an 128-bit state and a round key.
  | AESENC = 16
  /// Perform Last Round of an AES Encryption Flow.
  | AESENCLAST = 17
  /// Perform an inverse mix column transformation primitive.
  | AESIMC = 18
  /// Assist the creation of round keys with a key expansion schedule.
  | AESKEYGENASSIST = 19
  /// Logical AND.
  | AND = 20
  /// Bitwise AND of first source with inverted 2nd source operands.
  | ANDN = 21
  /// Bitwise Logical AND of Packed Double-Precision Floating-Point Values.
  | ANDNPD = 22
  /// Bitwise Logical AND of Packed Single-Precision Floating-Point Values.
  | ANDNPS = 23
  /// Bitwise Logical AND NOT of Packed Double-Precision Floating-Point Values.
  | ANDPD = 24
  /// Bitwise Logical AND NOT of Packed Single-Precision Floating-Point Values.
  | ANDPS = 25
  /// Adjust RPL Field of Segment Selector.
  | ARPL = 26
  /// Contiguous bitwise extract.
  | BEXTR = 27
  /// Blend Packed Double Precision Floating-Point Values.
  | BLENDPD = 28
  /// Blend Packed Single Precision Floating-Point Values.
  | BLENDPS = 29
  /// Variable Blend Packed Double Precision Floating-Point Values.
  | BLENDVPD = 30
  /// Variable Blend Packed Single Precision Floating-Point Values.
  | BLENDVPS = 31
  /// Extract lowest set bit.
  | BLSI = 32
  /// Set all lower bits below first set bit to 1.
  | BLSMSK = 33
  /// Reset lowest set bit.
  | BLSR = 34
  /// Check the address of a memory reference against a LowerBound.
  | BNDCL = 35
  /// Check Upper Bound.
  | BNDCN = 36
  /// Check Upper Bound.
  | BNDCU = 37
  /// Load Extended Bounds Using Address Translation.
  | BNDLDX = 38
  /// Create a LowerBound and a UpperBound in a register.
  | BNDMK = 39
  /// Move Bounds.
  | BNDMOV = 40
  /// Store bounds using address translation.
  | BNDSTX = 41
  /// Check Array Index Against Bounds.
  | BOUND = 42
  /// Bit Scan Forward.
  | BSF = 43
  /// Bit Scan Reverse.
  | BSR = 44
  /// Byte Swap.
  | BSWAP = 45
  /// Bit Test.
  | BT = 46
  /// Bit Test and Complement.
  | BTC = 47
  /// Bit Test and Reset.
  | BTR = 48
  /// Bit Test and Set.
  | BTS = 49
  /// Zero high bits starting from specified bit position.
  | BZHI = 50
  /// Far call.
  | CALLFar = 51
  /// Near call.
  | CALLNear = 52
  /// Convert Byte to Word.
  | CBW = 53
  /// Chinese national cryptographic algorithms.
  | CCS_ENCRYPT = 54
  /// Chinese national cryptographic algorithms.
  | CCS_HASH = 55
  /// Convert Doubleword to Quadword.
  | CDQ = 56
  /// Convert Doubleword to Quadword.
  | CDQE = 57
  /// Clear AC Flag in EFLAGS Register.
  | CLAC = 58
  /// Clear Carry Flag.
  | CLC = 59
  /// Clear Direction Flag.
  | CLD = 60
  /// Flush Cache Line.
  | CLFLUSH = 61
  /// Flush Cache Line Optimized.
  | CLFLUSHOPT = 62
  /// Clear Interrupt Flag.
  | CLI = 63
  /// Clear busy bit in a supervisor shadow stack token.
  | CLRSSBSY = 64
  /// Clear Task-Switched Flag in CR0.
  | CLTS = 65
  /// Cache Line Write Back.
  | CLWB = 66
  /// Complement Carry Flag.
  | CMC = 67
  /// Conditional Move (Move if above (CF = 0 and ZF = 0)).
  | CMOVA = 68
  /// Conditional Move (Move if above or equal (CF = 0)).
  | CMOVAE = 69
  /// Conditional Move (Move if below (CF = 1)).
  | CMOVB = 70
  /// Conditional Move (Move if below or equal (CF = 1 or ZF = 1)).
  | CMOVBE = 71
  /// Conditional move if carry.
  | CMOVC = 72
  /// Conditional Move (Move if greater (ZF = 0 and SF = OF)).
  | CMOVG = 73
  /// Conditional Move (Move if greater or equal (SF = OF)).
  | CMOVGE = 74
  /// Conditional Move (Move if less (SF <> OF)).
  | CMOVL = 75
  /// Conditional Move (Move if less or equal (ZF = 1 or SF <> OF)).
  | CMOVLE = 76
  /// Conditional move if not carry.
  | CMOVNC = 77
  /// Conditional Move (Move if not overflow (OF = 0)).
  | CMOVNO = 78
  /// Conditional Move (Move if not parity (PF = 0)).
  | CMOVNP = 79
  /// Conditional Move (Move if not sign (SF = 0)).
  | CMOVNS = 80
  /// Conditional Move (Move if not zero (ZF = 0)).
  | CMOVNZ = 81
  /// Conditional Move (Move if overflow (OF = 1)).
  | CMOVO = 82
  /// Conditional Move (Move if parity (PF = 1)).
  | CMOVP = 83
  /// Conditional Move (Move if sign (SF = 1)).
  | CMOVS = 84
  /// Conditional Move (Move if zero (ZF = 1)).
  | CMOVZ = 85
  /// Compare Two Operands.
  | CMP = 86
  /// Compare packed double-precision floating-point values.
  | CMPPD = 87
  /// Compare packed single-precision floating-point values.
  | CMPPS = 88
  /// Compare String Operands (byte).
  | CMPSB = 89
  /// Compare String Operands (dword) or Compare scalar dbl-precision FP values.
  | CMPSD = 90
  /// Compare String Operands (quadword).
  | CMPSQ = 91
  /// Compare scalar single-precision floating-point values.
  | CMPSS = 92
  /// Compare String Operands (word).
  | CMPSW = 93
  /// Compare and Exchange.
  | CMPXCHG = 94
  /// Compare and Exchange Bytes.
  | CMPXCHG16B = 95
  /// Compare and Exchange Bytes.
  | CMPXCHG8B = 96
  /// Compare Scalar Ordered Double-Precision FP Values and Set EFLAGS.
  | COMISD = 97
  /// Compare Scalar Ordered Single-Precision FP Values and Set EFLAGS.
  | COMISS = 98
  /// CPU Identification.
  | CPUID = 99
  /// Convert Quadword to Octaword.
  | CQO = 100
  /// Accumulate CRC32 Value.
  | CRC32 = 101
  /// Convert Packed Dword Integers to Packed Double-Precision FP Values.
  | CVTDQ2PD = 102
  /// Convert Packed Dword Integers to Packed Single-Precision FP Values.
  | CVTDQ2PS = 103
  /// Convert Packed Double-Precision FP Values to Packed Dword Integers.
  | CVTPD2DQ = 104
  /// Convert Packed Double-Precision FP Values to Packed Dword Integers.
  | CVTPD2PI = 105
  /// Convert Packed Double-Precision FP Values to Packed Single-Precision FP.
  | CVTPD2PS = 106
  /// Convert Packed Dword Integers to Packed Double-Precision FP Values.
  | CVTPI2PD = 107
  /// Convert Packed Dword Integers to Packed Single-Precision FP Values.
  | CVTPI2PS = 108
  /// Convert Packed Single-Precision FP Values to Packed Dword Integers.
  | CVTPS2DQ = 109
  /// Convert Packed Single-Precision FP Values to Packed Double-Precision FP.
  | CVTPS2PD = 110
  /// Convert Packed Single-Precision FP Values to Packed Dword Integers.
  | CVTPS2PI = 111
  /// Convert Scalar Double-Precision FP Value to Integer.
  | CVTSD2SI = 112
  /// Convert Scalar Double-Precision FP Value to Scalar Single-Precision FP.
  | CVTSD2SS = 113
  /// Convert Dword Integer to Scalar Double-Precision FP Value.
  | CVTSI2SD = 114
  /// Convert Dword Integer to Scalar Single-Precision FP Value.
  | CVTSI2SS = 115
  /// Convert Scalar Single-Precision FP Value to Scalar Double-Precision FP.
  | CVTSS2SD = 116
  /// Convert Scalar Single-Precision FP Value to Dword Integer.
  | CVTSS2SI = 117
  /// Convert with Truncation Packed Double-Precision FP Values to Packed Dword.
  | CVTTPD2DQ = 118
  /// Convert with Truncation Packed Double-Precision FP Values to Packed Dword.
  | CVTTPD2PI = 119
  /// Convert with Truncation Packed Single-Precision FP Values to Packed Dword.
  | CVTTPS2DQ = 120
  /// Convert with Truncation Packed Single-Precision FP Values to Packed Dword.
  | CVTTPS2PI = 121
  /// Convert with Truncation Scalar Double-Precision FP Value to Signed.
  | CVTTSD2SI = 122
  /// Convert with Truncation Scalar Single-Precision FP Value to Dword Integer.
  | CVTTSS2SI = 123
  /// Convert Word to Doubleword.
  | CWD = 124
  /// Convert Word to Doubleword.
  | CWDE = 125
  /// Decimal Adjust AL after Addition.
  | DAA = 126
  /// Decimal Adjust AL after Subtraction.
  | DAS = 127
  /// Decrement by 1.
  | DEC = 128
  /// Unsigned Divide.
  | DIV = 129
  /// Divide Packed Double-Precision Floating-Point Values.
  | DIVPD = 130
  /// Divide Packed Single-Precision Floating-Point Values.
  | DIVPS = 131
  /// Divide Scalar Double-Precision Floating-Point Values.
  | DIVSD = 132
  /// Divide Scalar Single-Precision Floating-Point Values.
  | DIVSS = 133
  /// Perform double-precision dot product for up to 2 elements and broadcast.
  | DPPD = 134
  /// Perform single-precision dot products for up to 4 elements and broadcast.
  | DPPS = 135
  /// Empty MMX Technology State.
  | EMMS = 136
  /// Execute an Enclave System Function of Specified Leaf Number.
  | ENCLS = 137
  /// Execute an Enclave User Function of Specified Leaf Number.
  | ENCLU = 138
  /// Terminate an Indirect Branch in 32-bit and Compatibility Mode.
  | ENDBR32 = 139
  /// Terminate an Indirect Branch in 64-bit Mode.
  | ENDBR64 = 140
  /// Make Stack Frame for Procedure Parameters.
  | ENTER = 141
  /// Extract Packed Floating-Point Values.
  | EXTRACTPS = 142
  /// Extract Field from Register.
  | EXTRQ = 143
  /// Compute 2x-1.
  | F2XM1 = 144
  /// Absolute Value.
  | FABS = 145
  /// Add.
  | FADD = 146
  /// Add and pop the register stack.
  | FADDP = 147
  /// Load Binary Coded Decimal.
  | FBLD = 148
  /// Store BCD Integer and Pop.
  | FBSTP = 149
  /// Change Sign.
  | FCHS = 150
  /// Clear Exceptions.
  | FCLEX = 151
  /// Floating-Point Conditional Move (if below (CF = 1)).
  | FCMOVB = 152
  /// Floating-Point Conditional Move (if below or equal (CF = 1 or ZF = 1)).
  | FCMOVBE = 153
  /// Floating-Point Conditional Move (if equal (ZF = 1)).
  | FCMOVE = 154
  /// Floating-Point Conditional Move (if not below (CF = 0)).
  | FCMOVNB = 155
  /// FP Conditional Move (if not below or equal (CF = 0 and ZF = 0)).
  | FCMOVNBE = 156
  /// Floating-Point Conditional Move (if not equal (ZF = 0)).
  | FCMOVNE = 157
  /// Floating-Point Conditional Move (if not unordered (PF = 0)).
  | FCMOVNU = 158
  /// Floating-Point Conditional Move (if unordered (PF = 1)).
  | FCMOVU = 159
  /// Compare Floating Point Values.
  | FCOM = 160
  /// Compare Floating Point Values and Set EFLAGS.
  | FCOMI = 161
  /// Compare Floating Point Values and Set EFLAGS.
  | FCOMIP = 162
  /// Compare Floating Point Values and pop register stack.
  | FCOMP = 163
  /// Compare Floating Point Values and pop register stack twice.
  | FCOMPP = 164
  /// Cosine.
  | FCOS = 165
  /// Decrement Stack-Top Pointer.
  | FDECSTP = 166
  /// Divide.
  | FDIV = 167
  /// Divide and pop the register stack.
  | FDIVP = 168
  /// Reverse Divide.
  | FDIVR = 169
  /// Reverse Divide and pop the register stack.
  | FDIVRP = 170
  /// Free Floating-Point Register.
  | FFREE = 171
  /// Performs FFREE ST(i) and pop stack.
  | FFREEP = 172
  /// Add.
  | FIADD = 173
  /// Compare Integer.
  | FICOM = 174
  /// Compare Integer and pop the register stack.
  | FICOMP = 175
  /// Divide.
  | FIDIV = 176
  /// Reverse Divide.
  | FIDIVR = 177
  /// Load Integer.
  | FILD = 178
  /// Multiply.
  | FIMUL = 179
  /// Increment Stack-Top Pointer.
  | FINCSTP = 180
  /// Initialize Floating-Point Unit.
  | FINIT = 181
  /// Store Integer.
  | FIST = 182
  /// Store Integer and pop the register stack.
  | FISTP = 183
  /// Store Integer with Truncation.
  | FISTTP = 184
  /// Subtract.
  | FISUB = 185
  /// Reverse Subtract.
  | FISUBR = 186
  /// Load Floating Point Value.
  | FLD = 187
  /// Load Constant (Push +1.0 onto the FPU register stack).
  | FLD1 = 188
  /// Load x87 FPU Control Word.
  | FLDCW = 189
  /// Load x87 FPU Environment.
  | FLDENV = 190
  /// Load Constant (Push log2e onto the FPU register stack).
  | FLDL2E = 191
  /// Load Constant (Push log210 onto the FPU register stack).
  | FLDL2T = 192
  /// Load Constant (Push log102 onto the FPU register stack).
  | FLDLG2 = 193
  /// Load Constant (Push loge2 onto the FPU register stack).
  | FLDLN2 = 194
  /// Load Constant (Push Pi onto the FPU register stack).
  | FLDPI = 195
  /// Load Constant (Push +0.0 onto the FPU register stack).
  | FLDZ = 196
  /// Multiply.
  | FMUL = 197
  /// Multiply and pop the register stack.
  | FMULP = 198
  /// Clear FP exception flags without checking for error conditions.
  | FNCLEX = 199
  /// Initialize FPU without checking error conditions.
  | FNINIT = 200
  /// No Operation.
  | FNOP = 201
  /// Save FPU state without checking error conditions.
  | FNSAVE = 202
  /// Store x87 FPU Control Word.
  | FNSTCW = 203
  /// Store FPU environment without checking error conditions.
  | FNSTENV = 204
  /// Store FPU status word without checking error conditions.
  | FNSTSW = 205
  /// Partial Arctangent.
  | FPATAN = 206
  /// Partial Remainder.
  | FPREM = 207
  /// Partial Remainder.
  | FPREM1 = 208
  /// Partial Tangent.
  | FPTAN = 209
  /// Round to Integer.
  | FRNDINT = 210
  /// Restore x87 FPU State.
  | FRSTOR = 211
  /// Store x87 FPU State.
  | FSAVE = 212
  /// Scale.
  | FSCALE = 213
  /// Sine.
  | FSIN = 214
  /// Sine and Cosine.
  | FSINCOS = 215
  /// Square Root.
  | FSQRT = 216
  /// Store Floating Point Value.
  | FST = 217
  /// Store FPU control word after checking error conditions.
  | FSTCW = 218
  /// Store x87 FPU Environment.
  | FSTENV = 219
  /// Store Floating Point Value.
  | FSTP = 220
  /// Store x87 FPU Status Word.
  | FSTSW = 221
  /// Subtract.
  | FSUB = 222
  /// Subtract and pop register stack.
  | FSUBP = 223
  /// Reverse Subtract.
  | FSUBR = 224
  /// Reverse Subtract and pop register stack.
  | FSUBRP = 225
  /// TEST.
  | FTST = 226
  /// Unordered Compare Floating Point Values.
  | FUCOM = 227
  /// Compare Floating Point Values and Set EFLAGS.
  | FUCOMI = 228
  /// Compare Floating Point Values and Set EFLAGS and pop register stack.
  | FUCOMIP = 229
  /// Unordered Compare Floating Point Values.
  | FUCOMP = 230
  /// Unordered Compare Floating Point Values.
  | FUCOMPP = 231
  /// Wait for FPU.
  | FWAIT = 232
  /// Examine ModR/M.
  | FXAM = 233
  /// Exchange Register Contents.
  | FXCH = 234
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR = 235
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR64 = 236
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE = 237
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE64 = 238
  /// Extract Exponent and Significand.
  | FXTRACT = 239
  /// compute y * log2x.
  | FYL2X = 240
  /// compute y * log2(x+1).
  | FYL2XP1 = 241
  /// GETSEC.
  | GETSEC = 242
  /// Galois Field Affine Transformation Inverse.
  | GF2P8AFFINEINVQB = 243
  /// Galois Field Affine Transformation.
  | GF2P8AFFINEQB = 244
  /// Galois Field Multiply Bytes.
  | GF2P8MULB = 245
  /// Packed Double-FP Horizontal Add.
  | HADDPD = 246
  /// Packed Single-FP Horizontal Add.
  | HADDPS = 247
  /// Halt.
  | HLT = 248
  /// Packed Double-FP Horizontal Subtract.
  | HSUBPD = 249
  /// Packed Single-FP Horizontal Subtract.
  | HSUBPS = 250
  /// Signed Divide.
  | IDIV = 251
  /// Signed Multiply.
  | IMUL = 252
  /// Input from Port.
  | IN = 253
  /// Increment by 1.
  | INC = 254
  /// Increment the shadow stack pointer (SSP).
  | INCSSPD = 255
  /// Increment the shadow stack pointer (SSP).
  | INCSSPQ = 256
  /// Input from Port to String.
  | INS = 257
  /// Input from Port to String (byte).
  | INSB = 258
  /// Input from Port to String (doubleword).
  | INSD = 259
  /// Insert Scalar Single-Precision Floating-Point Value.
  | INSERTPS = 260
  /// Inserts Field from a source Register to a destination Register.
  | INSERTQ = 261
  /// Input from Port to String (word).
  | INSW = 262
  /// Call to Interrupt (Interrupt vector specified by immediate byte).
  | INT = 263
  /// Call to Interrupt Procedure (Debug trap).
  | INT1 = 264
  /// Call to Interrupt (Interrupt 3-trap to debugger).
  | INT3 = 265
  /// Call to Interrupt (InteInterrupt 4-if overflow flag is 1).
  | INTO = 266
  /// Invalidate Internal Caches.
  | INVD = 267
  /// Invalidate Translations Derived from EPT.
  | INVEPT = 268
  /// Invalidate TLB Entries.
  | INVLPG = 269
  /// Invalidate Process-Context Identifier.
  | INVPCID = 270
  /// Invalidate Translations Based on VPID.
  | INVVPID = 271
  /// Return from interrupt.
  | IRET = 272
  /// Interrupt return (32-bit operand size).
  | IRETD = 273
  /// Interrupt return (64-bit operand size).
  | IRETQ = 274
  /// Interrupt return (16-bit operand size).
  | IRETW = 275
  /// Jump if Condition Is Met (Jump near if not below, CF = 0).
  | JAE = 276
  | JNC = 276
  | JNB = 276
  /// Jump if Condition Is Met (Jump short if below, CF = 1).
  | JC = 277
  | JNAE = 277
  | JB = 277
  /// Jump if Condition Is Met (Jump short if CX register is 0).
  | JCXZ = 278
  /// Jump if Condition Is Met (Jump short if ECX register is 0).
  | JECXZ = 279
  /// Jump if Condition Is Met (Jump near if not less, SF = OF).
  | JGE = 280
  | JNL = 280
  /// Far jmp.
  | JMPFar = 281
  /// Near jmp.
  | JMPNear = 282
  /// Jump if Condition Is Met (Jump short if below or equal, CF = 1 or ZF).
  | JNA = 283
  | JBE = 283
  /// Jump if Condition Is Met (Jump short if above, CF = 0 and ZF = 0).
  | JNBE = 284
  | JA = 284
  /// Jump if Cond Is Met (Jump short if less or equal, ZF = 1 or SF <> OF).
  | JNG = 285
  | JLE = 285
  /// Jump if Condition Is Met (Jump short if less, SF <> OF).
  | JNGE = 286
  | JL = 286
  /// Jump if Condition Is Met (Jump short if greater, ZF = 0 and SF = OF).
  | JNLE = 287
  | JG = 287
  /// Jump if Condition Is Met (Jump near if not overflow, OF = 0).
  | JNO = 288
  /// Jump if Condition Is Met (Jump near if not sign, SF = 0).
  | JNS = 289
  /// Jump if Condition Is Met (Jump near if not zero, ZF = 0).
  | JNZ = 290
  | JNE = 290
  /// Jump if Condition Is Met (Jump near if overflow, OF = 1).
  | JO = 291
  /// Jump if Condition Is Met (Jump near if parity, PF = 1).
  | JP = 292
  | JPE = 292
  /// Jump if Condition Is Met (Jump near if not parity, PF = 0).
  | JPO = 293
  | JNP = 293
  /// Jump if Condition Is Met (Jump short if RCX register is 0).
  | JRCXZ = 294
  /// Jump if Condition Is Met (Jump short if sign, SF = 1).
  | JS = 295
  /// Jump if Condition Is Met (Jump short if zero, ZF = 1).
  | JZ = 296
  | JE = 296
  /// Add two 8-bit opmasks.
  | KADDB = 297
  /// Add two 32-bit opmasks.
  | KADDD = 298
  /// Add two 64-bit opmasks.
  | KADDQ = 299
  /// Add two 16-bit opmasks.
  | KADDW = 300
  /// Logical AND two 8-bit opmasks.
  | KANDB = 301
  /// Logical AND two 32-bit opmasks.
  | KANDD = 302
  /// Logical AND NOT two 8-bit opmasks.
  | KANDNB = 303
  /// Logical AND NOT two 32-bit opmasks.
  | KANDND = 304
  /// Logical AND NOT two 64-bit opmasks.
  | KANDNQ = 305
  /// Logical AND NOT two 16-bit opmasks.
  | KANDNW = 306
  /// Logical AND two 64-bit opmasks.
  | KANDQ = 307
  /// Logical AND two 16-bit opmasks.
  | KANDW = 308
  /// Move from or move to opmask register of 8-bit data.
  | KMOVB = 309
  /// Move from or move to opmask register of 32-bit data.
  | KMOVD = 310
  /// Move from or move to opmask register of 64-bit data.
  | KMOVQ = 311
  /// Move from or move to opmask register of 16-bit data.
  | KMOVW = 312
  /// Bitwise NOT of two 8-bit opmasks.
  | KNOTB = 313
  /// Bitwise NOT of two 32-bit opmasks.
  | KNOTD = 314
  /// Bitwise NOT of two 64-bit opmasks.
  | KNOTQ = 315
  /// Bitwise NOT of two 16-bit opmasks.
  | KNOTW = 316
  /// Logical OR two 8-bit opmasks.
  | KORB = 317
  /// Logical OR two 32-bit opmasks.
  | KORD = 318
  /// Logical OR two 64-bit opmasks.
  | KORQ = 319
  /// Update EFLAGS according to the result of bitwise OR of two 8-bit opmasks.
  | KORTESTB = 320
  /// Update EFLAGS according to the result of bitwise OR of two 32-bit opmasks.
  | KORTESTD = 321
  /// Update EFLAGS according to the result of bitwise OR of two 64-bit opmasks.
  | KORTESTQ = 322
  /// Update EFLAGS according to the result of bitwise OR of two 16-bit opmasks.
  | KORTESTW = 323
  /// Logical OR two 16-bit opmasks.
  | KORW = 324
  /// Shift left 8-bitopmask by specified count.
  | KSHIFTLB = 325
  /// Shift left 32-bitopmask by specified count.
  | KSHIFTLD = 326
  /// Shift left 64-bitopmask by specified count.
  | KSHIFTLQ = 327
  /// Shift left 16-bitopmask by specified count.
  | KSHIFTLW = 328
  /// Shift right 8-bit opmask by specified count.
  | KSHIFTRB = 329
  /// Shift right 32-bit opmask by specified count.
  | KSHIFTRD = 330
  /// Shift right 64-bit opmask by specified count.
  | KSHIFTRQ = 331
  /// Shift right 16-bit opmask by specified count.
  | KSHIFTRW = 332
  /// Update EFLAGS according to result of bitwise TEST of two 8-bit opmasks.
  | KTESTB = 333
  /// Update EFLAGS according to result of bitwise TEST of two 32-bit opmasks.
  | KTESTD = 334
  /// Update EFLAGS according to result of bitwise TEST of two 64-bit opmasks.
  | KTESTQ = 335
  /// Update EFLAGS according to result of bitwise TEST of two 16-bit opmasks.
  | KTESTW = 336
  /// Unpack and interleave two 8-bit opmasks into 16-bit mask.
  | KUNPCKBW = 337
  /// Unpack and interleave two 32-bit opmasks into 64-bit mask.
  | KUNPCKDQ = 338
  /// Unpack and interleave two 16-bit opmasks into 32-bit mask.
  | KUNPCKWD = 339
  /// Bitwise logical XNOR of two 8-bit opmasks.
  | KXNORB = 340
  /// Bitwise logical XNOR of two 32-bit opmasks.
  | KXNORD = 341
  /// Bitwise logical XNOR of two 64-bit opmasks.
  | KXNORQ = 342
  /// Bitwise logical XNOR of two 16-bit opmasks.
  | KXNORW = 343
  /// Logical XOR of two 8-bit opmasks.
  | KXORB = 344
  /// Logical XOR of two 32-bit opmasks.
  | KXORD = 345
  /// Logical XOR of two 64-bit opmasks.
  | KXORQ = 346
  /// Logical XOR of two 16-bit opmasks.
  | KXORW = 347
  /// Load Status Flags into AH Register.
  | LAHF = 348
  /// Load Access Rights Byte.
  | LAR = 349
  /// Load Unaligned Integer 128 Bits.
  | LDDQU = 350
  /// Load MXCSR Register.
  | LDMXCSR = 351
  /// Load Far Pointer (DS).
  | LDS = 352
  /// Load Effective Address.
  | LEA = 353
  /// High Level Procedure Exit.
  | LEAVE = 354
  /// Load Far Pointer (ES).
  | LES = 355
  /// Load Fence.
  | LFENCE = 356
  /// Load Far Pointer (FS).
  | LFS = 357
  /// Load GlobalDescriptor Table Register.
  | LGDT = 358
  /// Load Far Pointer (GS).
  | LGS = 359
  /// Load Interrupt Descriptor Table Register.
  | LIDT = 360
  /// Load Local Descriptor Table Register.
  | LLDT = 361
  /// Load Machine Status Word.
  | LMSW = 362
  /// Assert LOCK# Signal Prefix.
  | LOCK = 363
  /// Load String (byte).
  | LODSB = 364
  /// Load String (doubleword).
  | LODSD = 365
  /// Load String (quadword).
  | LODSQ = 366
  /// Load String (word).
  | LODSW = 367
  /// Loop According to ECX Counter (count <> 0).
  | LOOP = 368
  /// Loop According to ECX Counter (count <> 0 and ZF = 1).
  | LOOPE = 369
  /// Loop According to ECX Counter (count <> 0 and ZF = 0).
  | LOOPNE = 370
  /// Load Segment Limit.
  | LSL = 371
  /// Load Far Pointer (SS).
  | LSS = 372
  /// Load Task Register.
  | LTR = 373
  /// the Number of Leading Zero Bits.
  | LZCNT = 374
  /// Store Selected Bytes of Double Quadword.
  | MASKMOVDQU = 375
  /// Store Selected Bytes of Quadword.
  | MASKMOVQ = 376
  /// Return Maximum Packed Double-Precision Floating-Point Values.
  | MAXPD = 377
  /// Return Maximum Packed Single-Precision Floating-Point Values.
  | MAXPS = 378
  /// Return Maximum Scalar Double-Precision Floating-Point Values.
  | MAXSD = 379
  /// Return Maximum Scalar Single-Precision Floating-Point Values.
  | MAXSS = 380
  /// Memory Fence.
  | MFENCE = 381
  /// Return Minimum Packed Double-Precision Floating-Point Values.
  | MINPD = 382
  /// Return Minimum Packed Single-Precision Floating-Point Values.
  | MINPS = 383
  /// Return Minimum Scalar Double-Precision Floating-Point Values.
  | MINSD = 384
  /// Return Minimum Scalar Single-Precision Floating-Point Values.
  | MINSS = 385
  /// Set Up Monitor Address.
  | MONITOR = 386
  /// Montgomery multiplier (PMM).
  | MONTMUL = 387
  /// Montgomery multiplier (PMM).
  | MONTMUL2 = 388
  /// MOV.
  | MOV = 389
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | MOVAPD = 390
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | MOVAPS = 391
  /// Move Data After Swapping Bytes.
  | MOVBE = 392
  /// Move Doubleword.
  | MOVD = 393
  /// Move One Double-FP and Duplicate.
  | MOVDDUP = 394
  /// Move Quadword from XMM to MMX Technology Register.
  | MOVDQ2Q = 395
  /// Move Aligned Double Quadword.
  | MOVDQA = 396
  /// Move Unaligned Double Quadword.
  | MOVDQU = 397
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | MOVHLPS = 398
  /// Move High Packed Double-Precision Floating-Point Value.
  | MOVHPD = 399
  /// Move High Packed Single-Precision Floating-Point Values.
  | MOVHPS = 400
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | MOVLHPS = 401
  /// Move Low Packed Double-Precision Floating-Point Value.
  | MOVLPD = 402
  /// Move Low Packed Single-Precision Floating-Point Values.
  | MOVLPS = 403
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | MOVMSKPD = 404
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | MOVMSKPS = 405
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQ = 406
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQA = 407
  /// Store Doubleword Using Non-Temporal Hint.
  | MOVNTI = 408
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPD = 409
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPS = 410
  /// Store of Quadword Using Non-Temporal Hint.
  | MOVNTQ = 411
  /// Move Quadword.
  | MOVQ = 412
  /// Move Quadword from MMX Technology to XMM Register.
  | MOVQ2DQ = 413
  /// Move Data from String to String (byte).
  | MOVSB = 414
  /// Move Data from String to String (doubleword).
  | MOVSD = 415
  /// Move Packed Single-FP High and Duplicate.
  | MOVSHDUP = 416
  /// Move Packed Single-FP Low and Duplicate.
  | MOVSLDUP = 417
  /// Move Data from String to String (quadword).
  | MOVSQ = 418
  /// Move Scalar Single-Precision Floating-Point Values.
  | MOVSS = 419
  /// Move Data from String to String (word).
  | MOVSW = 420
  /// Move with Sign-Extension.
  | MOVSX = 421
  /// Move with Sign-Extension (doubleword to quadword).
  | MOVSXD = 422
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | MOVUPD = 423
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | MOVUPS = 424
  /// Move with Zero-Extend.
  | MOVZX = 425
  /// Compute Multiple Packed Sums of Absolute Difference.
  | MPSADBW = 426
  /// Unsigned Multiply.
  | MUL = 427
  /// Multiply Packed Double-Precision Floating-Point Values.
  | MULPD = 428
  /// Multiply Packed Single-Precision Floating-Point Values.
  | MULPS = 429
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | MULSD = 430
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | MULSS = 431
  /// Unsigned multiply without affecting arithmetic flags.
  | MULX = 432
  /// Monitor Wait.
  | MWAIT = 433
  /// Two's Complement Negation.
  | NEG = 434
  /// No Operation.
  | NOP = 435
  /// One's Complement Negation.
  | NOT = 436
  /// Logical Inclusive OR.
  | OR = 437
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | ORPD = 438
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | ORPS = 439
  /// Output to Port.
  | OUT = 440
  /// Output String to Port.
  | OUTS = 441
  /// Output String to Port (byte).
  | OUTSB = 442
  /// Output String to Port (doubleword).
  | OUTSD = 443
  /// Output String to Port (word).
  | OUTSW = 444
  /// Computes the absolute value of each signed byte data element.
  | PABSB = 445
  /// Computes the absolute value of each signed 32-bit data element.
  | PABSD = 446
  /// Computes the absolute value of each signed 16-bit data element.
  | PABSW = 447
  /// Pack with Signed Saturation.
  | PACKSSDW = 448
  /// Pack with Signed Saturation.
  | PACKSSWB = 449
  /// Pack with Unsigned Saturation.
  | PACKUSDW = 450
  /// Pack with Unsigned Saturation.
  | PACKUSWB = 451
  /// Add Packed byte Integers.
  | PADDB = 452
  /// Add Packed Doubleword Integers.
  | PADDD = 453
  /// Add Packed Quadword Integers.
  | PADDQ = 454
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | PADDSB = 455
  /// Add Packed Signed Integers with Signed Saturation (word).
  | PADDSW = 456
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | PADDUSB = 457
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | PADDUSW = 458
  /// Add Packed word Integers.
  | PADDW = 459
  /// Packed Align Right.
  | PALIGNR = 460
  /// Logical AND.
  | PAND = 461
  /// Logical AND NOT.
  | PANDN = 462
  /// Spin Loop Hint.
  | PAUSE = 463
  /// Average Packed Integers (byte).
  | PAVGB = 464
  /// Average Packed Integers (word).
  | PAVGW = 465
  /// Variable Blend Packed Bytes.
  | PBLENDVB = 466
  /// Blend Packed Words.
  | PBLENDW = 467
  /// Perform carryless multiplication of two 64-bit numbers.
  | PCLMULQDQ = 468
  /// Compare Packed Data for Equal (byte).
  | PCMPEQB = 469
  /// Compare Packed Data for Equal (doubleword).
  | PCMPEQD = 470
  /// Compare Packed Data for Equal (quadword).
  | PCMPEQQ = 471
  /// Compare packed words for equal.
  | PCMPEQW = 472
  /// Packed Compare Explicit Length Strings, Return Index.
  | PCMPESTRI = 473
  /// Packed Compare Explicit Length Strings, Return Mask.
  | PCMPESTRM = 474
  /// Compare Packed Signed Integers for Greater Than (byte).
  | PCMPGTB = 475
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | PCMPGTD = 476
  /// Performs logical compare of greater-than on packed integer quadwords.
  | PCMPGTQ = 477
  /// Compare Packed Signed Integers for Greater Than (word).
  | PCMPGTW = 478
  /// Packed Compare Implicit Length Strings, Return Index.
  | PCMPISTRI = 479
  /// Packed Compare Implicit Length Strings, Return Mask.
  | PCMPISTRM = 480
  /// Parallel deposit of bits using a mask.
  | PDEP = 481
  /// Parallel extraction of bits using a mask.
  | PEXT = 482
  /// Extract Byte.
  | PEXTRB = 483
  /// Extract Dword.
  | PEXTRD = 484
  /// Extract Qword.
  | PEXTRQ = 485
  /// Extract Word.
  | PEXTRW = 486
  /// Packed Horizontal Add.
  | PHADDD = 487
  /// Packed Horizontal Add and Saturate.
  | PHADDSW = 488
  /// Packed Horizontal Add.
  | PHADDW = 489
  /// Packed Horizontal Word Minimum.
  | PHMINPOSUW = 490
  /// Packed Horizontal Subtract.
  | PHSUBD = 491
  /// Packed Horizontal Subtract and Saturate.
  | PHSUBSW = 492
  /// Packed Horizontal Subtract.
  | PHSUBW = 493
  /// Insert Byte.
  | PINSRB = 494
  /// Insert a dword value from 32-bit register or memory into an XMM register.
  | PINSRD = 495
  /// Insert a qword value from 64-bit register or memory into an XMM register.
  | PINSRQ = 496
  /// Insert Word.
  | PINSRW = 497
  /// Multiply and Add Packed Signed and Unsigned Bytes.
  | PMADDUBSW = 498
  /// Multiply and Add Packed Integers.
  | PMADDWD = 499
  /// Compare packed signed byte integers.
  | PMAXSB = 500
  /// Compare packed signed dword integers.
  | PMAXSD = 501
  /// Maximum of Packed Signed Word Integers.
  | PMAXSW = 502
  /// Maximum of Packed Unsigned Byte Integers.
  | PMAXUB = 503
  /// Compare packed unsigned dword integers.
  | PMAXUD = 504
  /// Compare packed unsigned word integers.
  | PMAXUW = 505
  /// Minimum of Packed Signed Byte Integers.
  | PMINSB = 506
  /// Compare packed signed dword integers.
  | PMINSD = 507
  /// Minimum of Packed Signed Word Integers.
  | PMINSW = 508
  /// Minimum of Packed Unsigned Byte Integers.
  | PMINUB = 509
  /// Minimum of Packed Dword Integers.
  | PMINUD = 510
  /// Compare packed unsigned word integers.
  | PMINUW = 511
  /// Move Byte Mask.
  | PMOVMSKB = 512
  /// Packed Move with Sign Extend.
  | PMOVSXBD = 513
  /// Packed Move with Sign Extend.
  | PMOVSXBQ = 514
  /// Packed Move with Sign Extend.
  | PMOVSXBW = 515
  /// Packed Move with Sign Extend.
  | PMOVSXDQ = 516
  /// Packed Move with Sign Extend.
  | PMOVSXWD = 517
  /// Packed Move with Sign Extend.
  | PMOVSXWQ = 518
  /// Packed Move with Zero Extend.
  | PMOVZXBD = 519
  /// Packed Move with Zero Extend.
  | PMOVZXBQ = 520
  /// Packed Move with Zero Extend.
  | PMOVZXBW = 521
  /// Packed Move with Zero Extend.
  | PMOVZXDQ = 522
  /// Packed Move with Zero Extend.
  | PMOVZXWD = 523
  /// Packed Move with Zero Extend.
  | PMOVZXWQ = 524
  /// Multiply Packed Doubleword Integers.
  | PMULDQ = 525
  /// Packed Multiply High with Round and Scale.
  | PMULHRSW = 526
  /// Multiply Packed Unsigned Integers and Store High Result.
  | PMULHUW = 527
  /// Multiply Packed Signed Integers and Store High Result.
  | PMULHW = 528
  /// Multiply Packed Integers and Store Low Result.
  | PMULLD = 529
  /// Multiply Packed Signed Integers and Store Low Result.
  | PMULLW = 530
  /// Multiply Packed Unsigned Doubleword Integers.
  | PMULUDQ = 531
  /// Pop a Value from the Stack.
  | POP = 532
  /// Pop All General-Purpose Registers (word).
  | POPA = 533
  /// Pop All General-Purpose Registers (doubleword).
  | POPAD = 534
  /// Return the Count of Number of Bits Set to 1.
  | POPCNT = 535
  /// Pop Stack into EFLAGS Register (lower 16bits EFLAGS).
  | POPF = 536
  /// Pop Stack into EFLAGS Register (EFLAGS).
  | POPFD = 537
  /// Pop Stack into EFLAGS Register (RFLAGS).
  | POPFQ = 538
  /// Bitwise Logical OR.
  | POR = 539
  /// Prefetch Data Into Caches (using NTA hint).
  | PREFETCHNTA = 540
  /// Prefetch Data Into Caches (using T0 hint).
  | PREFETCHT0 = 541
  /// Prefetch Data Into Caches (using T1 hint).
  | PREFETCHT1 = 542
  /// Prefetch Data Into Caches (using T2 hint).
  | PREFETCHT2 = 543
  /// Prefetch Data into Caches in Anticipation of a Write.
  | PREFETCHW = 544
  /// Prefetch Vector Data Into Caches with Intent to Write and T1 Hint.
  | PREFETCHWT1 = 545
  /// Compute Sum of Absolute Differences.
  | PSADBW = 546
  /// Packed Shuffle Bytes.
  | PSHUFB = 547
  /// Shuffle Packed Doublewords.
  | PSHUFD = 548
  /// Shuffle Packed High Words.
  | PSHUFHW = 549
  /// Shuffle Packed Low Words.
  | PSHUFLW = 550
  /// Shuffle Packed Words.
  | PSHUFW = 551
  /// Packed Sign Byte.
  | PSIGNB = 552
  /// Packed Sign Doubleword.
  | PSIGND = 553
  /// Packed Sign Word.
  | PSIGNW = 554
  /// Shift Packed Data Left Logical (doubleword).
  | PSLLD = 555
  /// Shift Double Quadword Left Logical.
  | PSLLDQ = 556
  /// Shift Packed Data Left Logical (quadword).
  | PSLLQ = 557
  /// Shift Packed Data Left Logical (word).
  | PSLLW = 558
  /// Shift Packed Data Right Arithmetic (doubleword).
  | PSRAD = 559
  /// Shift Packed Data Right Arithmetic (word).
  | PSRAW = 560
  /// Shift Packed Data Right Logical (doubleword).
  | PSRLD = 561
  /// Shift Double Quadword Right Logical.
  | PSRLDQ = 562
  /// Shift Packed Data Right Logical (quadword).
  | PSRLQ = 563
  /// Shift Packed Data Right Logical (word).
  | PSRLW = 564
  /// Subtract Packed Integers (byte).
  | PSUBB = 565
  /// Subtract Packed Integers (doubleword).
  | PSUBD = 566
  /// Subtract Packed Integers (quadword).
  | PSUBQ = 567
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | PSUBSB = 568
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | PSUBSW = 569
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | PSUBUSB = 570
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | PSUBUSW = 571
  /// Subtract Packed Integers (word).
  | PSUBW = 572
  /// Logical Compare.
  | PTEST = 573
  /// Unpack High Data.
  | PUNPCKHBW = 574
  /// Unpack High Data.
  | PUNPCKHDQ = 575
  /// Unpack High Data.
  | PUNPCKHQDQ = 576
  /// Unpack High Data.
  | PUNPCKHWD = 577
  /// Unpack Low Data.
  | PUNPCKLBW = 578
  /// Unpack Low Data.
  | PUNPCKLDQ = 579
  /// Unpack Low Data.
  | PUNPCKLQDQ = 580
  /// Unpack Low Data.
  | PUNPCKLWD = 581
  /// Push Word, Doubleword or Quadword Onto the Stack.
  | PUSH = 582
  /// Push All General-Purpose Registers (word).
  | PUSHA = 583
  /// Push All General-Purpose Registers (doubleword).
  | PUSHAD = 584
  /// Push EFLAGS Register onto the Stack (16bits of EFLAGS).
  | PUSHF = 585
  /// Push EFLAGS Register onto the Stack (EFLAGS).
  | PUSHFD = 586
  /// Push EFLAGS Register onto the Stack (RFLAGS).
  | PUSHFQ = 587
  /// Logical Exclusive OR.
  | PXOR = 588
  /// Rotate x bits (CF, r/m(x)) left once.
  | RCL = 589
  /// Compute reciprocals of packed single-precision floating-point values.
  | RCPPS = 590
  /// Compute reciprocal of scalar single-precision floating-point values.
  | RCPSS = 591
  /// Rotate x bits (CF, r/m(x)) right once.
  | RCR = 592
  /// Read FS Segment Base.
  | RDFSBASE = 593
  /// Read GS Segment Base.
  | RDGSBASE = 594
  /// Read from Model Specific Register.
  | RDMSR = 595
  /// Read Protection Key Rights for User Pages.
  | RDPKRU = 596
  /// Read Performance-Monitoring Counters.
  | RDPMC = 597
  /// Read Random Number.
  | RDRAND = 598
  /// Read Random SEED.
  | RDSEED = 599
  /// Read shadow stack point (SSP).
  | RDSSPD = 600
  /// Read shadow stack point (SSP).
  | RDSSPQ = 601
  /// Read Time-Stamp Counter.
  | RDTSC = 602
  /// Read Time-Stamp Counter and Processor ID.
  | RDTSCP = 603
  /// Repeat while ECX not zero.
  | REP = 604
  /// Repeat while equal/Repeat while zero.
  | REPE = 605
  /// Repeat while not equal/Repeat while not zero.
  | REPNE = 606
  /// Repeat while not equal/Repeat while not zero.
  | REPNZ = 607
  /// Repeat while equal/Repeat while zero.
  | REPZ = 608
  /// Far return.
  | RETFar = 609
  /// Far return w/ immediate.
  | RETFarImm = 610
  /// Near return.
  | RETNear = 611
  /// Near return w/ immediate .
  | RETNearImm = 612
  /// Rotate x bits r/m(x) left once.
  | ROL = 613
  /// Rotate x bits r/m(x) right once.
  | ROR = 614
  /// Rotate right without affecting arithmetic flags.
  | RORX = 615
  /// Round Packed Double Precision Floating-Point Values.
  | ROUNDPD = 616
  /// Round Packed Single Precision Floating-Point Values.
  | ROUNDPS = 617
  /// Round Scalar Double Precision Floating-Point Values.
  | ROUNDSD = 618
  /// Round Scalar Single Precision Floating-Point Values.
  | ROUNDSS = 619
  /// Resume from System Management Mode.
  | RSM = 620
  /// Compute reciprocals of square roots of packed single-precision FP values.
  | RSQRTPS = 621
  /// Compute reciprocal of square root of scalar single-precision FP values.
  | RSQRTSS = 622
  /// Restore a shadow stack pointer (SSP).
  | RSTORSSP = 623
  /// Store AH into Flags.
  | SAHF = 624
  /// Shift.
  | SAR = 625
  /// Shift arithmetic right.
  | SARX = 626
  /// Save previous shadow stack pointer (SSP).
  | SAVEPREVSSP = 627
  /// Integer Subtraction with Borrow.
  | SBB = 628
  /// Scan String (byte).
  | SCASB = 629
  /// Scan String (doubleword).
  | SCASD = 630
  /// Scan String (quadword).
  | SCASQ = 631
  /// Scan String (word).
  | SCASW = 632
  /// Set byte if above (CF = 0 and ZF = 0).
  | SETA = 633
  /// Set byte if below (CF = 1).
  | SETB = 634
  /// Set byte if below or equal (CF = 1 or ZF = 1).
  | SETBE = 635
  /// Set byte if greater (ZF = 0 and SF = OF).
  | SETG = 636
  /// Set byte if less (SF <> OF).
  | SETL = 637
  /// Set byte if less or equal (ZF = 1 or SF <> OF).
  | SETLE = 638
  /// Set byte if not below (CF = 0).
  | SETNB = 639
  /// Set byte if not less (SF = OF).
  | SETNL = 640
  /// Set byte if not overflow (OF = 0).
  | SETNO = 641
  /// Set byte if not parity (PF = 0).
  | SETNP = 642
  /// Set byte if not sign (SF = 0).
  | SETNS = 643
  /// Set byte if not zero (ZF = 0).
  | SETNZ = 644
  /// Set byte if overflow (OF = 1).
  | SETO = 645
  /// Set byte if parity (PF = 1).
  | SETP = 646
  /// Set byte if sign (SF = 1).
  | SETS = 647
  /// Set busy bit in a supervisor shadow stack token.
  | SETSSBSY = 648
  /// Set byte if sign (ZF = 1).
  | SETZ = 649
  /// Store Fence.
  | SFENCE = 650
  /// Store Global Descriptor Table Register.
  | SGDT = 651
  /// Perform an Intermediate Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG1 = 652
  /// Perform a Final Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG2 = 653
  /// Calculate SHA1 state E after four rounds.
  | SHA1NEXTE = 654
  /// Perform four rounds of SHA1 operations.
  | SHA1RNDS4 = 655
  /// Perform an intermediate calculation for the next 4 SHA256 message dwords.
  | SHA256MSG1 = 656
  /// Perform the final calculation for the next four SHA256 message dwords.
  | SHA256MSG2 = 657
  /// Perform two rounds of SHA256 operations.
  | SHA256RNDS2 = 658
  /// Shift.
  | SHL = 659
  /// Double Precision Shift Left.
  | SHLD = 660
  /// Shift logic left.
  | SHLX = 661
  /// Shift.
  | SHR = 662
  /// Double Precision Shift Right.
  | SHRD = 663
  /// Shift logic right.
  | SHRX = 664
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | SHUFPD = 665
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | SHUFPS = 666
  /// Store Interrupt Descriptor Table Register.
  | SIDT = 667
  /// Store Local Descriptor Table Register.
  | SLDT = 668
  /// Chinese national cryptographic algorithms.
  | SM2 = 669
  /// Store Machine Status Word.
  | SMSW = 670
  /// Compute packed square roots of packed double-precision FP values.
  | SQRTPD = 671
  /// Compute square roots of packed single-precision floating-point values.
  | SQRTPS = 672
  /// Compute scalar square root of scalar double-precision FP values.
  | SQRTSD = 673
  /// Compute square root of scalar single-precision floating-point values.
  | SQRTSS = 674
  /// Set AC Flag in EFLAGS Register.
  | STAC = 675
  /// Set Carry Flag.
  | STC = 676
  /// Set Direction Flag.
  | STD = 677
  /// Set Interrupt Flag.
  | STI = 678
  /// Store MXCSR Register State.
  | STMXCSR = 679
  /// Store String (store AL).
  | STOSB = 680
  /// Store String (store EAX).
  | STOSD = 681
  /// Store String (store RAX).
  | STOSQ = 682
  /// Store String (store AX).
  | STOSW = 683
  /// Store Task Register.
  | STR = 684
  /// Subtract.
  | SUB = 685
  /// Subtract Packed Double-Precision Floating-Point Values.
  | SUBPD = 686
  /// Subtract Packed Single-Precision Floating-Point Values.
  | SUBPS = 687
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | SUBSD = 688
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | SUBSS = 689
  /// Swap GS Base Register.
  | SWAPGS = 690
  /// Fast System Call.
  | SYSCALL = 691
  /// Fast System Call.
  | SYSENTER = 692
  /// Fast Return from Fast System Call.
  | SYSEXIT = 693
  /// Return From Fast System Call.
  | SYSRET = 694
  /// Logical Compare.
  | TEST = 695
  /// Count the Number of Trailing Zero Bits.
  | TZCNT = 696
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | UCOMISD = 697
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | UCOMISS = 698
  /// Undefined instruction (Raise invalid opcode exception).
  | UD0 = 699
  /// Undefined Instruction (Raise invalid opcode exception).
  | UD1 = 700
  /// Undefined Instruction (Raise invalid opcode exception).
  | UD2 = 701
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | UNPCKHPD = 702
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | UNPCKHPS = 703
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | UNPCKLPD = 704
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | UNPCKLPS = 705
  /// Packed Single-Precision Floating-Point Fused Multiply-Add.
  | V4FMADDPS = 706
  /// Scalar Single-Precision Floating-Point Fused Multiply-Add.
  | V4FMADDSS = 707
  /// Packed Single-Precision Floating-Point Fused Multiply-Add and Negate.
  | V4FNMADDPS = 708
  /// Scalar Single-Precision Floating-Point Fused Multiply-Add and Negate.
  | V4FNMADDSS = 709
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPD = 710
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPS = 711
  /// Add Scalar Double-Precision Floating-Point Values.
  | VADDSD = 712
  /// Add Scalar Single-Precision Floating-Point Values.
  | VADDSS = 713
  /// Packed Double-FP Add/Subtract.
  | VADDSUBPD = 714
  /// Packed Single-FP Add/Subtract.
  | VADDSUBPS = 715
  /// Perform One Round of an AES Decryption Flow.
  | VAESDEC = 716
  /// Perform Last Round of an AES Decryption Flow.
  | VAESDECLAST = 717
  /// Perform One Round of an AES Encryption Flow.
  | VAESENC = 718
  /// Perform Last Round of an AES Encryption Flow.
  | VAESENCLAST = 719
  /// Perform dword alignment of two concatenated source vectors.
  | VALIGND = 720
  /// Perform qword alignment of two concatenated source vectors.
  | VALIGNQ = 721
  /// Bitwise Logical AND of Packed Double-Precision Floating-Point Values.
  | VANDNPD = 722
  /// Bitwise Logical AND of Packed Single-Precision Floating-Point Values.
  | VANDNPS = 723
  /// Bitwise Logical AND NOT of Packed Double-Precision Floating-Point Values.
  | VANDPD = 724
  /// Bitwise Logical AND NOT of Packed Single-Precision Floating-Point Values.
  | VANDPS = 725
  /// Replace the VBLENDVPD instructions (using opmask as select control).
  | VBLENDMPD = 726
  /// Replace the VBLENDVPS instructions (using opmask as select control).
  | VBLENDMPS = 727
  /// Blend Packed Double-Precision Floats.
  | VBLENDPD = 728
  /// Blend Packed Single-Precision Floats.
  | VBLENDPS = 729
  /// Variable Blend Packed Double-Precision Floats.
  | VBLENDVPD = 730
  /// Variable Blend Packed Single-Precision Floats.
  | VBLENDVPS = 731
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTF128 = 732
  /// Broadcast 128 bits of int data in mem to low and high 128-bits in ymm1.
  | VBROADCASTI128 = 733
  /// Broadcast two dword elements.
  | VBROADCASTI32X2 = 734
  /// Broadcast four dword elements.
  | VBROADCASTI32X4 = 735
  /// Broadcast eight dword elements.
  | VBROADCASTI32X8 = 736
  /// Broadcast two qword elements.
  | VBROADCASTI64X2 = 737
  /// Broadcast four qword elements.
  | VBROADCASTI64X4 = 738
  /// Broadcast low double-precision floating-point element.
  | VBROADCASTSD = 739
  /// Broadcast Floating-Point Data.
  | VBROADCASTSS = 740
  /// Compare Packed Double-Precision Floating-Point Values.
  | VCMPPD = 741
  /// Compare Packed Single-Precision Floating-Point Values.
  | VCMPPS = 742
  /// Compare Scalar Double-Precision Floating-Point Values.
  | VCMPSD = 743
  /// Scalar Single-Precision Floating-Point Values.
  | VCMPSS = 744
  /// Compare Scalar Ordered Double-Precision FP Values and Set EFLAGS.
  | VCOMISD = 745
  /// Compare Scalar Ordered Single-Precision FP Values and Set EFLAGS.
  | VCOMISS = 746
  /// Compress packed DP elements of a vector.
  | VCOMPRESSPD = 747
  /// Compress packed SP elements of a vector.
  | VCOMPRESSPS = 748
  /// Convert two packed signed doubleword integers.
  | VCVTDQ2PD = 749
  /// Convert Packed Dword Integers to Packed Single-Precision FP Values.
  | VCVTDQ2PS = 750
  /// Convert Two Packed Single Data to One Packed BF16 Data.
  | VCVTNE2PS2BF16 = 751
  /// Convert Packed Single Data to Packed BF16 Data.
  | VCVTNEPS2BF16 = 752
  /// Convert Packed Double-Precision FP Values to Packed Doubleword Integers.
  | VCVTPD2DQ = 753
  /// Convert two packed double-precision floating-point values.
  | VCVTPD2PS = 754
  /// Convert Packed Double-Precision FP Values to Packed Quadword Integers.
  | VCVTPD2QQ = 755
  /// Convert Packed DP FP Values to Packed Unsigned DWord Integers.
  | VCVTPD2UDQ = 756
  /// Convert Packed DP FP Values to Packed Unsigned QWord Integers.
  | VCVTPD2UQQ = 757
  /// Convert 16-bit FP values to Single-Precision FP values.
  | VCVTPH2PS = 758
  /// Conv Packed Single-Precision FP Values to Packed Signed DWord Int Values.
  | VCVTPS2DQ = 759
  /// Conv Packed Single-Precision FP Values to Packed Dbl-Precision FP Values.
  | VCVTPS2PD = 760
  /// Convert Single-Precision FP value to 16-bit FP value.
  | VCVTPS2PH = 761
  /// Convert Packed SP FP Values to Packed Signed QWord Int Values.
  | VCVTPS2QQ = 762
  /// Convert Packed SP FP Values to Packed Unsigned DWord Int Values.
  | VCVTPS2UDQ = 763
  /// Convert Packed SP FP Values to Packed Unsigned QWord Int Values.
  | VCVTPS2UQQ = 764
  /// Convert Packed Quadword Integers to Packed Double-Precision FP Values.
  | VCVTQQ2PD = 765
  /// Convert Packed Quadword Integers to Packed Single-Precision FP Values.
  | VCVTQQ2PS = 766
  /// Convert Scalar Double-Precision FP Value to Integer.
  | VCVTSD2SI = 767
  /// Convert Scalar Double-Precision FP Val to Scalar Single-Precision FP Val.
  | VCVTSD2SS = 768
  /// Convert Scalar Double-Precision FP Value to Unsigned Doubleword Integer.
  | VCVTSD2USI = 769
  /// Convert Dword Integer to Scalar Double-Precision FP Value.
  | VCVTSI2SD = 770
  /// Convert Dword Integer to Scalar Single-Precision FP Value.
  | VCVTSI2SS = 771
  /// Convert Scalar Single-Precision FP Val to Scalar Double-Precision FP Val.
  | VCVTSS2SD = 772
  /// Convert Scalar Single-Precision FP Value to Dword Integer.
  | VCVTSS2SI = 773
  /// Convert Scalar Single-Precision FP Value to Unsigned Doubleword Integer.
  | VCVTSS2USI = 774
  /// Conv with Trunc Packed Double-Precision FP Val to Packed Dword Integers.
  | VCVTTPD2DQ = 775
  /// Convert with Truncation Packed DP FP Values to Packed QWord Integers.
  | VCVTTPD2QQ = 776
  /// Convert with Truncation Packed DP FP Values to Packed Unsigned DWord Int.
  | VCVTTPD2UDQ = 777
  /// Convert with Truncation Packed DP FP Values to Packed Unsigned QWord Int.
  | VCVTTPD2UQQ = 778
  /// Conv with Trunc Packed Single-Precision FP Val to Packed Dword Integers.
  | VCVTTPS2DQ = 779
  /// Convert with Truncation Packed SP FP Values to Packed Signed QWord Int.
  | VCVTTPS2QQ = 780
  /// Convert with Truncation Packed SP FP Values to Packed Unsigned DWord Int.
  | VCVTTPS2UDQ = 781
  /// Convert with Truncation Packed SP FP Values to Packed Unsigned QWord Int.
  | VCVTTPS2UQQ = 782
  /// Convert with Truncation Scalar Double-Precision FP Value to Signed.
  | VCVTTSD2SI = 783
  /// Convert with Truncation Scalar DP FP Value to Unsigned Integer.
  | VCVTTSD2USI = 784
  /// Convert with Truncation Scalar Single-Precision FP Value to Dword Integer.
  | VCVTTSS2SI = 785
  /// Convert with Truncation Scalar Single-Precision FP Value to Unsigned Int.
  | VCVTTSS2USI = 786
  /// Convert Packed Unsigned DWord Integers to Packed DP FP Values.
  | VCVTUDQ2PD = 787
  /// Convert Packed Unsigned DWord Integers to Packed SP FP Values.
  | VCVTUDQ2PS = 788
  /// Convert Packed Unsigned QWord Integers to Packed DP FP Values.
  | VCVTUQQ2PD = 789
  /// Convert Packed Unsigned QWord Integers to Packed SP FP Values.
  | VCVTUQQ2PS = 790
  /// Convert an signed integer to the low DP FP elem and merge to a vector.
  | VCVTUSI2SD = 791
  /// Convert an signed integer to the low SP FP elem and merge to a vector.
  | VCVTUSI2SS = 792
  /// Convert an unsigned integer to the low DP FP elem and merge to a vector.
  | VCVTUSI2USD = 793
  /// Convert an unsigned integer to the low SP FP elem and merge to a vector.
  | VCVTUSI2USS = 794
  /// Double Block Packed Sum-Absolute-Differences (SAD) on Unsigned Bytes.
  | VDBPSADBW = 795
  /// Divide Packed Double-Precision Floating-Point Values.
  | VDIVPD = 796
  /// Divide Packed Single-Precision Floating-Point Values.
  | VDIVPS = 797
  /// Divide Scalar Double-Precision Floating-Point Values.
  | VDIVSD = 798
  /// Divide Scalar Single-Precision Floating-Point Values.
  | VDIVSS = 799
  /// Dot Product of BF16 Pairs Accumulated into Packed Single Precision.
  | VDPBF16PS = 800
  /// Packed Double-Precision Dot Products.
  | VDPPD = 801
  /// Packed Single-Precision Dot Products.
  | VDPPS = 802
  /// Verify a Segment for Reading.
  | VERR = 803
  /// Verify a Segment for Writing.
  | VERW = 804
  /// Compute approximate base-2 exponential of packed DP FP elems of a vector.
  | VEXP2PD = 805
  /// Compute approximate base-2 exponential of packed SP FP elems of a vector.
  | VEXP2PS = 806
  /// Compute approximate base-2 exponential of the low DP FP elem of a vector.
  | VEXP2SD = 807
  /// Compute approximate base-2 exponential of the low SP FP elem of a vector.
  | VEXP2SS = 808
  /// Load Sparse Packed Double-Precision FP Values from Dense Memory.
  | VEXPANDPD = 809
  /// Load Sparse Packed Single-Precision FP Values from Dense Memory.
  | VEXPANDPS = 810
  /// Extract Packed Floating-Point Values.
  | VEXTRACTF128 = 811
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTF32X4 = 812
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTF32X8 = 813
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTF64X2 = 814
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTF64X4 = 815
  /// Extract packed Integer Values.
  | VEXTRACTI128 = 816
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTI32X4 = 817
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTI32X8 = 818
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTI64X2 = 819
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTI64X4 = 820
  /// Extract From Packed Single-Precision Floats.
  | VEXTRACTPS = 821
  /// Fix Up Special Packed Float64 Values.
  | VFIXUPIMMPD = 822
  /// Fix Up Special Packed Float32 Values.
  | VFIXUPIMMPS = 823
  /// Fix Up Special Scalar Float64 Value.
  | VFIXUPIMMSD = 824
  /// Fix Up Special Scalar Float32 Value.
  | VFIXUPIMMSS = 825
  /// Fused Multiply-Add of Packed Double-Precision Floating-Point Values.
  | VFMADD132PD = 826
  /// Fused Multiply-Add of Packed Single-Precision Floating-Point Values.
  | VFMADD132PS = 827
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD132SD = 828
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD132SS = 829
  /// Fused Multiply-Add of Packed Double-Precision Floating-Point Values.
  | VFMADD213PD = 830
  /// Fused Multiply-Add of Packed Single-Precision Floating-Point Values.
  | VFMADD213PS = 831
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD213SD = 832
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD213SS = 833
  /// Fused Multiply-Add of Packed Double-Precision Floating-Point Value.
  | VFMADD231PD = 834
  /// Fused Multiply-Add of Packed Single-Precision Floating-Point Values.
  | VFMADD231PS = 835
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD231SD = 836
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD231SS = 837
  /// Multiply and Add Packed Double-Precision Floating-Point(Only AMD).
  | VFMADDPD = 838
  /// Multiply and Add Packed Single-Precision Floating-Point(Only AMD).
  | VFMADDPS = 839
  /// Multiply and Add Scalar Double-Precision Floating-Point(Only AMD).
  | VFMADDSD = 840
  /// Multiply and Add Scalar Single-Precision Floating-Point(Only AMD).
  | VFMADDSS = 841
  /// Fused Multiply-Alternating Add/Sub of Packed Double-Precision FP Values.
  | VFMADDSUB132PD = 842
  /// Fused Multiply-Alternating Add/Sub of Packed Single-Precision FP Values.
  | VFMADDSUB132PS = 843
  /// Fused Multiply-Alternating Add/Sub of Packed Double-Precision FP Values.
  | VFMADDSUB213PD = 844
  /// Fused Multiply-Alternating Add/Sub of Packed Single-Precision FP Values.
  | VFMADDSUB213PS = 845
  /// Fused Multiply-Alternating Add/Sub of Packed Double-Precision FP Values.
  | VFMADDSUB231PD = 846
  /// Fused Multiply-Alternating Add/Sub of Packed Single-Precision FP Values.
  | VFMADDSUB231PS = 847
  /// Fused Multiply-Subtract of Packed Double-Precision Floating-Point Values.
  | VFMSUB132PD = 848
  /// Fused Multiply-Subtract of Packed Single-Precision Floating-Point Values.
  | VFMSUB132PS = 849
  /// Fused Multiply-Subtract of Scalar Double-Precision Floating-Point Values.
  | VFMSUB132SD = 850
  /// Fused Multiply-Subtract of Scalar Single-Precision Floating-Point Values.
  | VFMSUB132SS = 851
  /// Fused Multiply-Subtract of Packed Double-Precision Floating-Point Values.
  | VFMSUB213PD = 852
  /// Fused Multiply-Subtract of Packed Single-Precision Floating-Point Values.
  | VFMSUB213PS = 853
  /// Fused Multiply-Subtract of Scalar Double-Precision Floating-Point Values.
  | VFMSUB213SD = 854
  /// Fused Multiply-Subtract of Scalar Single-Precision Floating-Point Values.
  | VFMSUB213SS = 855
  /// Fused Multiply-Subtract of Packed Double-Precision Floating-Point Values.
  | VFMSUB231PD = 856
  /// Fused Multiply-Subtract of Packed Single-Precision Floating-Point Values.
  | VFMSUB231PS = 857
  /// Fused Multiply-Subtract of Scalar Double-Precision Floating-Point Values.
  | VFMSUB231SD = 858
  /// Fused Multiply-Subtract of Scalar Single-Precision Floating-Point Values.
  | VFMSUB231SS = 859
  /// Fused Multiply-Alternating Sub/Add of Packed Double-Precision FP Values.
  | VFMSUBADD132PD = 860
  /// Fused Multiply-Alternating Sub/Add of Packed Single-Precision FP Values.
  | VFMSUBADD132PS = 861
  /// Fused Multiply-Alternating Sub/Add of Packed Double-Precision FP Values.
  | VFMSUBADD213PD = 862
  /// Fused Multiply-Alternating Sub/Add of Packed Single-Precision FP Values.
  | VFMSUBADD213PS = 863
  /// Fused Multiply-Alternating Sub/Add of Packed Double-Precision FP Values.
  | VFMSUBADD231PD = 864
  /// Fused Multiply-Alternating Sub/Add of Packed Single-Precision FP Values.
  | VFMSUBADD231PS = 865
  /// Fused Negative Multiply-Add of Packed Double-Precision FP Values.
  | VFNMADD132PD = 866
  /// Fused Negative Mul-Add of Packed Single-Precision Floating-Point Values.
  | VFNMADD132PS = 867
  /// Fused Negative Multiply-Add of Scalar Double-Precision FP Values.
  | VFNMADD132SD = 868
  /// Fused Negative Mul-Add of Scalar Single-Precision Floating-Point Values.
  | VFNMADD132SS = 869
  /// Fused Negative Multiply-Add of Packed Double-Precision FP Values.
  | VFNMADD213PD = 870
  /// Fused Negative Mul-Add of Packed Single-Precision Floating-Point Values.
  | VFNMADD213PS = 871
  /// Fused Negative Multiply-Add of Scalar Double-Precision FP Values.
  | VFNMADD213SD = 872
  /// Fused Negative Mul-Add of Scalar Single-Precision Floating-Point Values.
  | VFNMADD213SS = 873
  /// Fused Negative Multiply-Add of Packed Double-Precision FP Values.
  | VFNMADD231PD = 874
  /// Fused Negative Mul-Add of Packed Single-Precision Floating-Point Values.
  | VFNMADD231PS = 875
  /// Fused Negative Multiply-Add of Scalar Double-Precision FP Values.
  | VFNMADD231SD = 876
  /// Fused Negative Mul-Add of Scalar Single-Precision Floating-Point Values.
  | VFNMADD231SS = 877
  /// Fused Negative Multiply-Subtract of Packed Double-Precision FP Values.
  | VFNMSUB132PD = 878
  /// Fused Negative Multiply-Subtract of Packed Single-Precision FP Values.
  | VFNMSUB132PS = 879
  /// Fused Negative Multiply-Subtract of Scalar Double-Precision FP Values.
  | VFNMSUB132SD = 880
  /// Fused Negative Multiply-Subtract of Scalar Single-Precision FP Values.
  | VFNMSUB132SS = 881
  /// Fused Negative Multiply-Subtract of Packed Double-Precision FP Values.
  | VFNMSUB213PD = 882
  /// Fused Negative Multiply-Subtract of Packed Single-Precision FP Values.
  | VFNMSUB213PS = 883
  /// Fused Negative Multiply-Subtract of Scalar Double-Precision FP Values.
  | VFNMSUB213SD = 884
  /// Fused Negative Multiply-Subtract of Scalar Single-Precision FP Values.
  | VFNMSUB213SS = 885
  /// Fused Negative Multiply-Subtract of Packed Double-Precision FP Values.
  | VFNMSUB231PD = 886
  /// Fused Negative Multiply-Subtract of Packed Single-Precision FP Values.
  | VFNMSUB231PS = 887
  /// Fused Negative Multiply-Subtract of Scalar Double-Precision FP Values.
  | VFNMSUB231SD = 888
  /// Fused Negative Multiply-Subtract of Scalar Single-Precision FP Values.
  | VFNMSUB231SS = 889
  /// Tests Types Of a Packed Float64 Values.
  | VFPCLASSPD = 890
  /// Tests Types Of a Packed Float32 Values.
  | VFPCLASSPS = 891
  /// Tests Types Of a Scalar Float64 Values.
  | VFPCLASSSD = 892
  /// Tests Types Of a Scalar Float32 Values.
  | VFPCLASSSS = 893
  /// Gather Packed DP FP Values Using Signed Dword/Qword Indices.
  | VGATHERDPD = 894
  /// Gather Packed SP FP values Using Signed Dword/Qword Indices.
  | VGATHERDPS = 895
  /// Sparse prefetch of packed DP FP vector with T0 hint using dword indices.
  | VGATHERPF0DPD = 896
  /// Sparse prefetch of packed SP FP vector with T0 hint using dword indices.
  | VGATHERPF0DPS = 897
  /// Sparse prefetch of packed DP FP vector with T0 hint using qword indices.
  | VGATHERPF0QPD = 898
  /// Sparse prefetch of packed SP FP vector with T0 hint using qword indices.
  | VGATHERPF0QPS = 899
  /// Sparse prefetch of packed DP FP vector with T1 hint using dword indices.
  | VGATHERPF1DPD = 900
  /// Sparse prefetch of packed SP FP vector with T1 hint using dword indices.
  | VGATHERPF1DPS = 901
  /// Sparse prefetch of packed DP FP vector with T1 hint using qword indices.
  | VGATHERPF1QPD = 902
  /// Sparse prefetch of packed SP FP vector with T1 hint using qword indices.
  | VGATHERPF1QPS = 903
  /// Gather Packed DP FP Values Using Signed Dword/Qword Indices.
  | VGATHERQPD = 904
  /// Gather Packed SP FP values Using Signed Dword/Qword Indices.
  | VGATHERQPS = 905
  /// Convert Exponents of Packed DP FP Values to DP FP Values.
  | VGETEXPPD = 906
  /// Convert Exponents of Packed SP FP Values to SP FP Values.
  | VGETEXPPS = 907
  /// Convert Exponents of Scalar DP FP Values to DP FP Value.
  | VGETEXPSD = 908
  /// Convert Exponents of Scalar SP FP Values to SP FP Value.
  | VGETEXPSS = 909
  /// Extract Float64 Vector of Normalized Mantissas from Float64 Vector.
  | VGETMANTPD = 910
  /// Extract Float32 Vector of Normalized Mantissas from Float32 Vector.
  | VGETMANTPS = 911
  /// Extract Float64 of Normalized Mantissas from Float64 Scalar.
  | VGETMANTSD = 912
  /// Extract Float32 Vector of Normalized Mantissa from Float32 Vector.
  | VGETMANTSS = 913
  /// Galois Field Affine Transformation Inverse.
  | VGF2P8AFFINEINVQB = 914
  /// Galois Field Affine Transformation.
  | VGF2P8AFFINEQB = 915
  /// Galois Field Multiply Bytes.
  | VGF2P8MULB = 916
  /// Packed Double-FP Horizontal Add.
  | VHADDPD = 917
  /// Packed Single-FP Horizontal Add.
  | VHADDPS = 918
  /// Packed Double-FP Horizontal Subtract.
  | VHSUBPD = 919
  /// Packed Single-FP Horizontal Subtract.
  | VHSUBPS = 920
  /// Insert Packed Floating-Point Values.
  | VINSERTF128 = 921
  /// Insert Packed Floating-Point Values.
  | VINSERTF32X4 = 922
  /// Insert Packed Floating-Point Values.
  | VINSERTF64X2 = 923
  /// Insert Packed Floating-Point Values.
  | VINSERTF64X4 = 924
  /// Insert Packed Integer Values.
  | VINSERTI128 = 925
  /// Insert 256 bits of packed doubleword integer values.
  | VINSERTI32X8 = 926
  /// Insert Packed Floating-Point Values.
  | VINSERTI64X2 = 927
  /// Insert 256 bits of packed quadword integer values.
  | VINSERTI64X4 = 928
  /// Insert Into Packed Single-Precision Floats.
  | VINSERTPS = 929
  /// Load Unaligned Integer 128 Bits.
  | VLDDQU = 930
  /// Store Selected Bytes of Double Quadword.
  | VMASKMOVDQU = 931
  /// Conditional SIMD Packed Loads and Stores.
  | VMASKMOVPD = 932
  /// Conditional SIMD Packed Loads and Stores.
  | VMASKMOVPS = 933
  /// Return Maximum Packed Double-Precision Floating-Point Values.
  | VMAXPD = 934
  /// Maximum of Packed Single-Precision Floating-Point Values.
  | VMAXPS = 935
  /// Return Maximum Scalar Double-Precision Floating-Point Value.
  | VMAXSD = 936
  /// Return Maximum Scalar Single-Precision Floating-Point Value.
  | VMAXSS = 937
  /// Call to VM Monitor.
  | VMCALL = 938
  /// Clear Virtual-Machine Control Structure.
  | VMCLEAR = 939
  /// Invoke VM function.
  | VMFUNC = 940
  /// Return Minimum Packed Double-Precision Floating-Point Values.
  | VMINPD = 941
  /// Return Minimum Packed Single-Precision Floating-Point Values.
  | VMINPS = 942
  /// Return Minimum Scalar Double-Precision Floating-Point Value.
  | VMINSD = 943
  /// Return Minimum Scalar Single-Precision Floating-Point Value.
  | VMINSS = 944
  /// Launch Virtual Machine.
  | VMLAUNCH = 945
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | VMOVAPD = 946
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | VMOVAPS = 947
  /// Move Doubleword.
  | VMOVD = 948
  /// Move One Double-FP and Duplicate.
  | VMOVDDUP = 949
  /// Move Aligned Double Quadword.
  | VMOVDQA = 950
  /// Move Aligned Double Quadword.
  | VMOVDQA32 = 951
  /// Move Aligned Double Quadword.
  | VMOVDQA64 = 952
  /// Move Unaligned Double Quadword.
  | VMOVDQU = 953
  /// VMOVDQU with 16-bit granular conditional update.
  | VMOVDQU16 = 954
  /// Move Unaligned Double Quadword.
  | VMOVDQU32 = 955
  /// Move Unaligned Double Quadword.
  | VMOVDQU64 = 956
  /// VMOVDQU with 8-bit granular conditional update.
  | VMOVDQU8 = 957
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | VMOVHLPS = 958
  /// Move High Packed Double-Precision Floating-Point Value.
  | VMOVHPD = 959
  /// Move High Packed Single-Precision Floating-Point Values.
  | VMOVHPS = 960
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | VMOVLHPS = 961
  /// Move Low Packed Double-Precision Floating-Point Value.
  | VMOVLPD = 962
  /// Move Low Packed Single-Precision Floating-Point Values.
  | VMOVLPS = 963
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | VMOVMSKPD = 964
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | VMOVMSKPS = 965
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | VMOVNTDQ = 966
  /// Load Double Quadword Non-temporal Aligned.
  | VMOVNTDQA = 967
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPD = 968
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPS = 969
  /// Move Quadword.
  | VMOVQ = 970
  /// Move Data from String to String (doubleword).
  | VMOVSD = 971
  /// Move Packed Single-FP High and Duplicate.
  | VMOVSHDUP = 972
  /// Move Packed Single-FP Low and Duplicate.
  | VMOVSLDUP = 973
  /// Move Scalar Single-Precision Floating-Point Values.
  | VMOVSS = 974
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | VMOVUPD = 975
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | VMOVUPS = 976
  /// Compute Multiple Packed Sums of Absolute Difference.
  | VMPSADBW = 977
  /// Load Pointer to Virtual-Machine Control Structure.
  | VMPTRLD = 978
  /// Store Pointer to Virtual-Machine Control Structure.
  | VMPTRST = 979
  /// Reads a component from the VMCS and stores it into a destination operand.
  | VMREAD = 980
  /// Resume Virtual Machine.
  | VMRESUME = 981
  /// Multiply Packed Double-Precision Floating-Point Values.
  | VMULPD = 982
  /// Multiply Packed Single-Precision Floating-Point Values.
  | VMULPS = 983
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | VMULSD = 984
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | VMULSS = 985
  /// Writes a component to the VMCS from a source operand.
  | VMWRITE = 986
  /// Leave VMX Operation.
  | VMXOFF = 987
  /// Enter VMX Operation.
  | VMXON = 988
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | VORPD = 989
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | VORPS = 990
  /// Compute Intersection Between dwords.
  | VP2INTERSECTD = 991
  /// Compute Intersection Between qwords.
  | VP2INTERSECTQ = 992
  /// Dot Product of Signed Words with Dword Accumulation.
  | VP4DPWSSD = 993
  /// Dot Product of Signed Words with Dword Accumulation and Saturation.
  | VP4DPWSSDS = 994
  /// Packed Absolute Value (byte).
  | VPABSB = 995
  /// Packed Absolute Value (dword).
  | VPABSD = 996
  /// Packed Absolute Value (qword).
  | VPABSQ = 997
  /// Packed Absolute Value (word).
  | VPABSW = 998
  /// Pack with Signed Saturation.
  | VPACKSSDW = 999
  /// Pack with Signed Saturation.
  | VPACKSSWB = 1000
  /// Pack with Unsigned Saturation.
  | VPACKUSDW = 1001
  /// Pack with Unsigned Saturation.
  | VPACKUSWB = 1002
  /// Add Packed byte Integers.
  | VPADDB = 1003
  /// Add Packed Doubleword Integers.
  | VPADDD = 1004
  /// Add Packed Quadword Integers.
  | VPADDQ = 1005
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | VPADDSB = 1006
  /// Add Packed Signed Integers with Signed Saturation (word).
  | VPADDSW = 1007
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPADDUSB = 1008
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | VPADDUSW = 1009
  /// Add Packed word Integers.
  | VPADDW = 1010
  /// Packed Align Right.
  | VPALIGNR = 1011
  /// Logical AND.
  | VPAND = 1012
  /// Logical AND.
  | VPANDD = 1013
  /// Logical AND NOT.
  | VPANDN = 1014
  /// Logical AND.
  | VPANDQ = 1015
  /// Average Packed Integers (byte).
  | VPAVGB = 1016
  /// Average Packed Integers (word).
  | VPAVGW = 1017
  /// Blend Packed Dwords.
  | VPBLENDD = 1018
  /// Blend Byte/Word Vectors Using an Opmask Control.
  | VPBLENDMB = 1019
  /// Blend Int32/Int64 Vectors Using an OpMask Control.
  | VPBLENDMD = 1020
  /// Blend qword elements using opmask as select control.
  | VPBLENDMQ = 1021
  /// Blend word elements using opmask as select control.
  | VPBLENDMW = 1022
  /// Variable Blend Packed Bytes.
  | VPBLENDVB = 1023
  /// Blend Packed Words.
  | VPBLENDW = 1024
  /// Broadcast Integer Data.
  | VPBROADCASTB = 1025
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTD = 1026
  /// Broadcast Mask to Vector Register.
  | VPBROADCASTM = 1027
  /// Broadcast low byte value in k1.
  | VPBROADCASTMB2Q = 1028
  /// Broadcast low word value in k1.
  | VPBROADCASTMW2D = 1029
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTQ = 1030
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTW = 1031
  /// Carry-Less Multiplication Quadword.
  | VPCLMULQDQ = 1032
  /// Compare packed signed bytes using specified primitive.
  | VPCMPB = 1033
  /// Compare packed signed dwords using specified primitive.
  | VPCMPD = 1034
  /// Compare Packed Data for Equal (byte).
  | VPCMPEQB = 1035
  /// Compare Packed Data for Equal (doubleword).
  | VPCMPEQD = 1036
  /// Compare Packed Data for Equal (quadword).
  | VPCMPEQQ = 1037
  /// Compare Packed Data for Equal (word).
  | VPCMPEQW = 1038
  /// Packed Compare Explicit Length Strings, Return Index.
  | VPCMPESTRI = 1039
  /// Packed Compare Explicit Length Strings, Return Mask.
  | VPCMPESTRM = 1040
  /// Compare Packed Signed Integers for Greater Than (byte).
  | VPCMPGTB = 1041
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | VPCMPGTD = 1042
  /// Compare Packed Data for Greater Than (qword).
  | VPCMPGTQ = 1043
  /// Compare Packed Signed Integers for Greater Than (word).
  | VPCMPGTW = 1044
  /// Packed Compare Implicit Length Strings, Return Index.
  | VPCMPISTRI = 1045
  /// Packed Compare Implicit Length Strings, Return Mask.
  | VPCMPISTRM = 1046
  /// Compare packed signed quadwords using specified primitive.
  | VPCMPQ = 1047
  /// Compare packed unsigned bytes using specified primitive.
  | VPCMPUB = 1048
  /// Compare packed unsigned dwords using specified primitive.
  | VPCMPUD = 1049
  /// Compare packed unsigned quadwords using specified primitive.
  | VPCMPUQ = 1050
  /// Compare packed unsigned words using specified primitive.
  | VPCMPUW = 1051
  /// Compare packed signed words using specified primitive.
  | VPCMPW = 1052
  /// Compare packed unsigned bytes using specified primitive.
  | VPCMUB = 1053
  /// Compare packed unsigned dwords using specified primitive.
  | VPCMUD = 1054
  /// Compare packed unsigned quadwords using specified primitive.
  | VPCMUQ = 1055
  /// Compare packed unsigned words using specified primitive.
  | VPCMUW = 1056
  /// Store Sparse Packed Byte Integer Values into Dense Memory/Register.
  | VPCOMPRESSB = 1057
  /// Store Sparse Packed Doubleword Integer Values into Dense Memory/Register.
  | VPCOMPRESSD = 1058
  /// Store Sparse Packed Quadword Integer Values into Dense Memory/Register.
  | VPCOMPRESSQ = 1059
  /// Store Sparse Packed Word Integer Values into Dense Memory/Register.
  | VPCOMPRESSW = 1060
  /// Detect conflicts within a vector of packed 32/64-bit integers.
  | VPCONFLICTD = 1061
  /// Detect conflicts within a vector of packed 64-bit integers.
  | VPCONFLICTQ = 1062
  /// Multiply and Add Unsigned and Signed Bytes.
  | VPDPBUSD = 1063
  /// Multiply and Add Unsigned and Signed Bytes with Saturation.
  | VPDPBUSDS = 1064
  /// Multiply and Add Signed Word Integers.
  | VPDPWSSD = 1065
  /// Multiply and Add Signed Word Integers with Saturation.
  | VPDPWSSDS = 1066
  /// Permute Floating-Point Values.
  | VPERM2F128 = 1067
  /// Permute Integer Values.
  | VPERM2I128 = 1068
  /// Permute packed bytes elements.
  | VPERMB = 1069
  /// Permute Packed Doublewords/Words Elements.
  | VPERMD = 1070
  /// Full Permute of Bytes from Two Tables Overwriting the Index.
  | VPERMI2B = 1071
  /// Full permute of two tables of dword elements overwriting the index vector.
  | VPERMI2D = 1072
  /// Full permute of two tables of DP elements overwriting the index vector.
  | VPERMI2PD = 1073
  /// Full permute of two tables of SP elements overwriting the index vector.
  | VPERMI2PS = 1074
  /// Full permute of two tables of qword elements overwriting the index vector.
  | VPERMI2Q = 1075
  /// Full Permute From Two Tables Overwriting the Index.
  | VPERMI2W = 1076
  /// Permute Double-Precision Floating-Point Values.
  | VPERMILPD = 1077
  /// Permute Single-Precision Floating-Point Values.
  | VPERMILPS = 1078
  /// Permute Double-Precision Floating-Point Elements.
  | VPERMPD = 1079
  /// Permute Single-Precision Floating-Point Elements.
  | VPERMPS = 1080
  /// Qwords Element Permutation.
  | VPERMQ = 1081
  /// Full permute of two tables of byte elements overwriting one source table.
  | VPERMT2B = 1082
  /// Full permute of two tables of dword elements overwriting one source table.
  | VPERMT2D = 1083
  /// Full permute of two tables of DP elements overwriting one source table.
  | VPERMT2PD = 1084
  /// Full permute of two tables of SP elements overwriting one source table.
  | VPERMT2PS = 1085
  /// Full permute of two tables of qword elements overwriting one source table.
  | VPERMT2Q = 1086
  /// Full permute of two tables of word elements overwriting one source table.
  | VPERMT2W = 1087
  /// Permute packed word elements.
  | VPERMW = 1088
  /// Load Sparse Packed Byte Integer Values from Dense Memory / Register.
  | VPEXPANDB = 1089
  /// Load Sparse Packed Doubleword Integer Values from Dense Memory / Register.
  | VPEXPANDD = 1090
  /// Load Sparse Packed Quadword Integer Values from Dense Memory / Register.
  | VPEXPANDQ = 1091
  /// Load Sparse Packed Word Integer Values from Dense Memory / Register.
  | VPEXPANDW = 1092
  /// Extract Byte.
  | VPEXTRB = 1093
  /// Extract Dword.
  | VPEXTRD = 1094
  /// Extract Qword.
  | VPEXTRQ = 1095
  /// Extract Word.
  | VPEXTRW = 1096
  /// Gather packed dword values using signed Dword/Qword indices.
  | VPGATHERDD = 1097
  /// Gather Packed Qword Values Using Signed Dword/Qword Indices.
  | VPGATHERDQ = 1098
  /// Gather Packed Dword Values Using Signed Dword/Qword Indices.
  | VPGATHERQD = 1099
  /// Gather Packed Qword Values Using Signed Dword/Qword Indices.
  | VPGATHERQQ = 1100
  /// Packed Horizontal Add (32-bit).
  | VPHADDD = 1101
  /// Packed Horizontal Add and Saturate (16-bit).
  | VPHADDSW = 1102
  /// Packed Horizontal Add (16-bit).
  | VPHADDW = 1103
  /// Packed Horizontal Word Minimum.
  | VPHMINPOSUW = 1104
  /// Packed Horizontal Subtract (32-bit).
  | VPHSUBD = 1105
  /// Packed Horizontal Subtract and Saturate (16-bit).
  | VPHSUBSW = 1106
  /// Packed Horizontal Subtract (16-bit).
  | VPHSUBW = 1107
  /// Insert Byte.
  | VPINSRB = 1108
  /// Insert Dword.
  | VPINSRD = 1109
  /// Insert Qword.
  | VPINSRQ = 1110
  /// Insert Word.
  | VPINSRW = 1111
  /// Count the number of leading zero bits of packed dword elements.
  | VPLZCNTD = 1112
  /// Count the number of leading zero bits of packed qword elements.
  | VPLZCNTQ = 1113
  /// Packed Multiply of Unsigned 52-bit and Add High 52-bit Products.
  | VPMADD52HUQ = 1114
  /// Packed Multiply of Unsigned 52-bit and Add Low 52-bit Products.
  | VPMADD52LUQ = 1115
  /// Multiply and Add Packed Signed and Unsigned Bytes.
  | VPMADDUBSW = 1116
  /// Multiply and Add Packed Integers.
  | VPMADDWD = 1117
  /// Conditional SIMD Integer Packed Loads and Stores.
  | VPMASKMOVD = 1118
  /// Conditional SIMD Integer Packed Loads and Stores.
  | VPMASKMOVQ = 1119
  /// Maximum of Packed Signed Integers (byte).
  | VPMAXSB = 1120
  /// Maximum of Packed Signed Integers (dword).
  | VPMAXSD = 1121
  /// Compute maximum of packed signed 64-bit integer elements.
  | VPMAXSQ = 1122
  /// Maximum of Packed Signed Word Integers.
  | VPMAXSW = 1123
  /// Maximum of Packed Unsigned Byte Integers.
  | VPMAXUB = 1124
  /// Maximum of Packed Unsigned Integers (dword).
  | VPMAXUD = 1125
  /// Compute maximum of packed unsigned 64-bit integer elements.
  | VPMAXUQ = 1126
  /// Maximum of Packed Unsigned Integers (word).
  | VPMAXUW = 1127
  /// Minimum of Packed Signed Integers (byte).
  | VPMINSB = 1128
  /// Minimum of Packed Signed Integers (dword).
  | VPMINSD = 1129
  /// Compute minimum of packed signed 64-bit integer elements.
  | VPMINSQ = 1130
  /// Minimum of Packed Signed Word Integers.
  | VPMINSW = 1131
  /// Minimum of Packed Unsigned Byte Integers.
  | VPMINUB = 1132
  /// Minimum of Packed Dword Integers.
  | VPMINUD = 1133
  /// Compute minimum of packed unsigned 64-bit integer elements.
  | VPMINUQ = 1134
  /// Minimum of Packed Unsigned Integers (word).
  | VPMINUW = 1135
  /// Convert a vector register in 32/64-bit granularity to an opmask register.
  | VPMOVB2D = 1136
  /// Convert a Vector Register to a Mask.
  | VPMOVB2M = 1137
  /// Convert dword vector register to mask register.
  | VPMOVD2M = 1138
  /// Down Convert DWord to Byte.
  | VPMOVDB = 1139
  /// Down Convert DWord to Word.
  | VPMOVDW = 1140
  /// Convert opmask register to vector register in 8-bit granularity.
  | VPMOVM2B = 1141
  /// Convert opmask register to vector register in 32-bit granularity.
  | VPMOVM2D = 1142
  /// Convert opmask register to vector register in 64-bit granularity.
  | VPMOVM2Q = 1143
  /// Convert opmask register to vector register in 16-bit granularity.
  | VPMOVM2W = 1144
  /// Move Byte Mask.
  | VPMOVMSKB = 1145
  /// Convert qword vector register to mask register.
  | VPMOVQ2M = 1146
  /// Down Convert QWord to Byte.
  | VPMOVQB = 1147
  /// Down Convert QWord to DWord.
  | VPMOVQD = 1148
  /// Down Convert QWord to Word.
  | VPMOVQW = 1149
  /// Down Convert DWord to Byte.
  | VPMOVSDB = 1150
  /// Down Convert DWord to Word.
  | VPMOVSDW = 1151
  /// Down Convert QWord to Byte.
  | VPMOVSQB = 1152
  /// Down Convert QWord to Dword.
  | VPMOVSQD = 1153
  /// Down Convert QWord to Word.
  | VPMOVSQW = 1154
  /// Down Convert Word to Byte.
  | VPMOVSWB = 1155
  /// Packed Move with Sign Extend (8-bit to 32-bit).
  | VPMOVSXBD = 1156
  /// Packed Move with Sign Extend (8-bit to 64-bit).
  | VPMOVSXBQ = 1157
  /// Packed Move with Sign Extend (8-bit to 16-bit).
  | VPMOVSXBW = 1158
  /// Packed Move with Sign Extend (32-bit to 64-bit).
  | VPMOVSXDQ = 1159
  /// Packed Move with Sign Extend (16-bit to 32-bit).
  | VPMOVSXWD = 1160
  /// Packed Move with Sign Extend (16-bit to 64-bit).
  | VPMOVSXWQ = 1161
  /// Down Convert DWord to Byte.
  | VPMOVUSDB = 1162
  /// Down Convert DWord to Word.
  | VPMOVUSDW = 1163
  /// Down Convert QWord to Byte.
  | VPMOVUSQB = 1164
  /// Down Convert QWord to DWord.
  | VPMOVUSQD = 1165
  /// Down Convert QWord to Word.
  | VPMOVUSQW = 1166
  /// Down Convert Word to Byte.
  | VPMOVUSWB = 1167
  /// Convert a vector register in 16-bit granularity to an opmask register.
  | VPMOVW2M = 1168
  /// Down convert word elements in a vector to byte elements using truncation.
  | VPMOVWB = 1169
  /// Packed Move with Zero Extend (8-bit to 32-bit).
  | VPMOVZXBD = 1170
  /// Packed Move with Zero Extend (8-bit to 64-bit).
  | VPMOVZXBQ = 1171
  /// Packed Move with Zero Extend (8-bit to 16-bit).
  | VPMOVZXBW = 1172
  /// Packed Move with Zero Extend (32-bit to 64-bit).
  | VPMOVZXDQ = 1173
  /// Packed Move with Zero Extend (16-bit to 32-bit).
  | VPMOVZXWD = 1174
  /// Packed Move with Zero Extend (16-bit to 64-bit).
  | VPMOVZXWQ = 1175
  /// Multiply Packed Doubleword Integers.
  | VPMULDQ = 1176
  /// Packed Multiply High with Round and Scale.
  | VPMULHRSW = 1177
  /// Multiply Packed Unsigned Integers and Store High Result.
  | VPMULHUW = 1178
  /// Multiply Packed Signed Integers and Store High Result.
  | VPMULHW = 1179
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLD = 1180
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLQ = 1181
  /// Multiply Packed Signed Integers and Store Low Result.
  | VPMULLW = 1182
  /// Select Packed Unaligned Bytes from Quadword Sources.
  | VPMULTISHIFTQB = 1183
  /// Multiply Packed Unsigned Doubleword Integers.
  | VPMULUDQ = 1184
  /// Return the Count of Number of Bits Set to 1 in byte.
  | VPOPCNTB = 1185
  /// Return the Count of Number of Bits Set to 1 in dword.
  | VPOPCNTD = 1186
  /// Return the Count of Number of Bits Set to 1 in qword.
  | VPOPCNTQ = 1187
  /// Return the Count of Number of Bits Set to 1 in word.
  | VPOPCNTW = 1188
  /// Bitwise Logical OR.
  | VPOR = 1189
  /// Bitwise Logical OR.
  | VPORD = 1190
  /// Bitwise Logical OR.
  | VPORQ = 1191
  /// Rotate dword elem left by a constant shift count with conditional update.
  | VPROLD = 1192
  /// Rotate qword elem left by a constant shift count with conditional update.
  | VPROLQ = 1193
  /// Rotate dword element left by shift counts specified.
  | VPROLVD = 1194
  /// Rotate qword element left by shift counts specified.
  | VPROLVQ = 1195
  /// Rotate dword element right by a constant shift count.
  | VPRORD = 1196
  /// Rotate qword element right by a constant shift count.
  | VPRORQ = 1197
  /// Rotate dword element right by shift counts specified.
  | VPRORRD = 1198
  /// Rotate qword element right by shift counts specified.
  | VPRORRQ = 1199
  /// Rotate dword element right by shift counts specified.
  | VPRORVD = 1200
  /// Rotate qword element right by shift counts specified.
  | VPRORVQ = 1201
  /// Compute Sum of Absolute Differences.
  | VPSADBW = 1202
  /// Scatter dword elements in a vector to memory using dword indices.
  | VPSCATTERDD = 1203
  /// Scatter qword elements in a vector to memory using dword indices.
  | VPSCATTERDQ = 1204
  /// Scatter dword elements in a vector to memory using qword indices.
  | VPSCATTERQD = 1205
  /// Scatter qword elements in a vector to memory using qword indices.
  | VPSCATTERQQ = 1206
  /// Concatenate and Shift Packed Data Left Logical.
  | VPSHLDD = 1207
  /// Concatenate and Shift Packed Data Left Logical.
  | VPSHLDQ = 1208
  /// Concatenate and Variable Shift Packed Data Left Logical.
  | VPSHLDVD = 1209
  /// Concatenate and Variable Shift Packed Data Left Logical.
  | VPSHLDVQ = 1210
  /// Concatenate and Variable Shift Packed Data Left Logical.
  | VPSHLDVW = 1211
  /// Concatenate and Shift Packed Data Left Logical.
  | VPSHLDW = 1212
  /// Concatenate and Shift Packed Data Right Logical.
  | VPSHRDD = 1213
  /// Concatenate and Shift Packed Data Right Logical.
  | VPSHRDQ = 1214
  /// Concatenate and Variable Shift Packed Data Right Logical.
  | VPSHRDVD = 1215
  /// Concatenate and Variable Shift Packed Data Right Logical.
  | VPSHRDVQ = 1216
  /// Concatenate and Variable Shift Packed Data Right Logical.
  | VPSHRDVW = 1217
  /// Concatenate and Shift Packed Data Right Logical.
  | VPSHRDW = 1218
  /// Packed Shuffle Bytes.
  | VPSHUFB = 1219
  /// Shuffle Bits from Quadword Elements Using Byte Indexes into Mask.
  | VPSHUFBITQMB = 1220
  /// Shuffle Packed Doublewords.
  | VPSHUFD = 1221
  /// Shuffle Packed High Words.
  | VPSHUFHW = 1222
  /// Shuffle Packed Low Words.
  | VPSHUFLW = 1223
  /// Packed SIGN (byte).
  | VPSIGNB = 1224
  /// Packed SIGN (doubleword).
  | VPSIGND = 1225
  /// Packed SIGN (word).
  | VPSIGNW = 1226
  /// Shift Packed Data Left Logical (doubleword).
  | VPSLLD = 1227
  /// Shift Double Quadword Left Logical.
  | VPSLLDQ = 1228
  /// Shift Packed Data Left Logical (quadword).
  | VPSLLQ = 1229
  /// Variable Bit Shift Left Logical.
  | VPSLLVD = 1230
  /// Variable Bit Shift Left Logical.
  | VPSLLVQ = 1231
  /// Variable Bit Shift Left Logical.
  | VPSLLVW = 1232
  /// Shift Packed Data Left Logical (word).
  | VPSLLW = 1233
  /// Shift Packed Data Right Arithmetic (doubleword).
  | VPSRAD = 1234
  /// Shift qwords right by a constant shift count and shifting in sign bits.
  | VPSRAQ = 1235
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVD = 1236
  /// Shift qwords right by shift counts in a vector and shifting in sign bits.
  | VPSRAVQ = 1237
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVW = 1238
  /// Shift Packed Data Right Arithmetic (word).
  | VPSRAW = 1239
  /// Shift Packed Data Right Logical (doubleword).
  | VPSRLD = 1240
  /// Shift Double Quadword Right Logical.
  | VPSRLDQ = 1241
  /// Shift Packed Data Right Logical (quadword).
  | VPSRLQ = 1242
  /// Variable Bit Shift Right Logical.
  | VPSRLVD = 1243
  /// Variable Bit Shift Right Logical.
  | VPSRLVQ = 1244
  /// Variable Bit Shift Right Logical.
  | VPSRLVW = 1245
  /// Shift Packed Data Right Logical (word).
  | VPSRLW = 1246
  /// Subtract Packed Integers (byte).
  | VPSUBB = 1247
  /// Subtract Packed Integers (doubleword).
  | VPSUBD = 1248
  /// Subtract Packed Integers (quadword).
  | VPSUBQ = 1249
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | VPSUBSB = 1250
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | VPSUBSW = 1251
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPSUBUSB = 1252
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | VPSUBUSW = 1253
  /// Subtract Packed Integers (word).
  | VPSUBW = 1254
  /// Perform bitwise ternary logic operation of three vectors.
  | VPTERLOGD = 1255
  /// Perform bitwise ternary logic operation of three vectors.
  | VPTERLOGQ = 1256
  /// Bitwise Ternary Logic.
  | VPTERNLOGD = 1257
  /// Bitwise Ternary Logic.
  | VPTERNLOGQ = 1258
  /// Logical Compare.
  | VPTEST = 1259
  /// Perform bitwise AND of byte elems of two vecs and write results to opmask.
  | VPTESTMB = 1260
  /// Perform bitwise AND of dword elems of 2-vecs and write results to opmask.
  | VPTESTMD = 1261
  /// Perform bitwise AND of qword elems of 2-vecs and write results to opmask.
  | VPTESTMQ = 1262
  /// Perform bitwise AND of word elems of two vecs and write results to opmask.
  | VPTESTMW = 1263
  /// Perform bitwise NAND of byte elems of 2-vecs and write results to opmask.
  | VPTESTNMB = 1264
  /// Perform bitwise NAND of dword elems of 2-vecs and write results to opmask.
  | VPTESTNMD = 1265
  /// Perform bitwise NAND of qword elems of 2-vecs and write results to opmask.
  | VPTESTNMQ = 1266
  /// Perform bitwise NAND of word elems of 2-vecs and write results to opmask.
  | VPTESTNMW = 1267
  /// Unpack High Data.
  | VPUNPCKHBW = 1268
  /// Unpack High Data.
  | VPUNPCKHDQ = 1269
  /// Unpack High Data.
  | VPUNPCKHQDQ = 1270
  /// Unpack High Data.
  | VPUNPCKHWD = 1271
  /// Unpack Low Data.
  | VPUNPCKLBW = 1272
  /// Unpack Low Data.
  | VPUNPCKLDQ = 1273
  /// Unpack Low Data.
  | VPUNPCKLQDQ = 1274
  /// Unpack Low Data.
  | VPUNPCKLWD = 1275
  /// Logical Exclusive OR.
  | VPXOR = 1276
  /// Bitwise XOR of packed doubleword integers.
  | VPXORD = 1277
  /// Bitwise XOR of packed quadword integers.
  | VPXORQ = 1278
  /// Range Restriction Calculation For Packed Pairs of Float64 Values.
  | VRANGEPD = 1279
  /// Range Restriction Calculation For Packed Pairs of Float32 Values.
  | VRANGEPS = 1280
  /// Range Restriction Calculation From a pair of Scalar Float64 Values.
  | VRANGESD = 1281
  /// Range Restriction Calculation From a Pair of Scalar Float32 Values.
  | VRANGESS = 1282
  /// Compute Approximate Reciprocals of Packed Float64 Values.
  | VRCP14PD = 1283
  /// Compute Approximate Reciprocals of Packed Float32 Values.
  | VRCP14PS = 1284
  /// Compute Approximate Reciprocal of Scalar Float64 Value.
  | VRCP14SD = 1285
  /// Compute Approximate Reciprocal of Scalar Float32 Value.
  | VRCP14SS = 1286
  /// Computes the reciprocal approximation of the float64 values.
  | VRCP28PD = 1287
  /// Computes the reciprocal approximation of the float32 values.
  | VRCP28PS = 1288
  /// Computes the reciprocal approximation of the low float64 value.
  | VRCP28SD = 1289
  /// Computes the reciprocal approximation of the low float32 value.
  | VRCP28SS = 1290
  /// Compute reciprocals of packed single-precision floating-point values.
  | VRCPPS = 1291
  /// Compute Reciprocal of Scalar Single-Precision Floating-Point Values.
  | VRCPSS = 1292
  /// Perform Reduction Transformation on Packed Float64 Values.
  | VREDUCEPD = 1293
  /// Perform Reduction Transformation on Packed Float32 Values.
  | VREDUCEPS = 1294
  /// Perform a Reduction Transformation on a Scalar Float64 Value.
  | VREDUCESD = 1295
  /// Perform a Reduction Transformation on a Scalar Float32 Value.
  | VREDUCESS = 1296
  /// Round Packed Float64 Values To Include A Given Number Of Fraction Bits.
  | VRNDSCALEPD = 1297
  /// Round Packed Float32 Values To Include A Given Number Of Fraction Bits.
  | VRNDSCALEPS = 1298
  /// Round Scalar Float64 Value To Include A Given Number Of Fraction Bits.
  | VRNDSCALESD = 1299
  /// Round Scalar Float32 Value To Include A Given Number Of Fraction Bits.
  | VRNDSCALESS = 1300
  /// Round Packed Double-Precision Values.
  | VROUNDPD = 1301
  /// Round Packed Single-Precision Values.
  | VROUNDPS = 1302
  /// Round Scalar Double-Precision Value.
  | VROUNDSD = 1303
  /// Round Scalar Single-Precision Value.
  | VROUNDSS = 1304
  /// Compute Approximate Reciprocals of Square Roots of Packed Float64 Values.
  | VRSQRT14PD = 1305
  /// Compute Approximate Reciprocals of Square Roots of Packed Float32 Values.
  | VRSQRT14PS = 1306
  /// Compute Approximate Reciprocal of Square Root of Scalar Float64 Value.
  | VRSQRT14SD = 1307
  /// Compute Approximate Reciprocal of Square Root of Scalar Float32 Value.
  | VRSQRT14SS = 1308
  /// Computes the reciprocal square root of the float64 values.
  | VRSQRT28PD = 1309
  /// Computes the reciprocal square root of the float32 values.
  | VRSQRT28PS = 1310
  /// Computes the reciprocal square root of the low float64 value.
  | VRSQRT28SD = 1311
  /// Computes the reciprocal square root of the low float32 value.
  | VRSQRT28SS = 1312
  /// Compute Reciprocals of Square Roots of Packed Single-Precision FP Values.
  | VRSQRTPS = 1313
  /// Compute Reciprocal of Square Root of Scalar Single-Precision FP Value.
  | VRSQRTSS = 1314
  /// Scale Packed Float64 Values With Float64 Values.
  | VSCALEFPD = 1315
  /// Scale Packed Float32 Values With Float32 Values.
  | VSCALEFPS = 1316
  /// Scale Scalar Float64 Values With Float64 Values.
  | VSCALEFSD = 1317
  /// Scale Scalar Float32 Value With Float32 Value.
  | VSCALEFSS = 1318
  /// Multiply packed DP FP elements of a vector by powers.
  | VSCALEPD = 1319
  /// Multiply packed SP FP elements of a vector by powers.
  | VSCALEPS = 1320
  /// Multiply the low DP FP element of a vector by powers.
  | VSCALESD = 1321
  /// Multiply the low SP FP element of a vector by powers.
  | VSCALESS = 1322
  /// Scatter SP/DP FP elements in a vector to memory using dword indices.
  | VSCATTERDD = 1323
  /// Scatter packed double with signed dword indices.
  | VSCATTERDPD = 1324
  /// Scatter packed single with signed dword indices.
  | VSCATTERDPS = 1325
  /// Scatter SP/DP FP elements in a vector to memory using dword indices.
  | VSCATTERDQ = 1326
  /// Sparse prefetch packed DP FP with T0 hint to write using dword indices.
  | VSCATTERPF0DPD = 1327
  /// Sparse prefetch packed SP FP with T0 hint to write using dword indices.
  | VSCATTERPF0DPS = 1328
  /// Sparse prefetch packed DP FP with T0 hint to write using qword indices.
  | VSCATTERPF0QPD = 1329
  /// Sparse prefetch packed SP FP with T0 hint to write using qword indices.
  | VSCATTERPF0QPS = 1330
  /// Sparse prefetch packed DP FP with T1 hint to write using dword indices.
  | VSCATTERPF1DPD = 1331
  /// Sparse prefetch packed SP FP with T1 hint to write using dword indices.
  | VSCATTERPF1DPS = 1332
  /// Sparse prefetch packed DP FP with T1 hint to write using qword indices.
  | VSCATTERPF1QPD = 1333
  /// Sparse prefetch packed SP FP with T1 hint to write using qword indices.
  | VSCATTERPF1QPS = 1334
  /// Scatter SP/DP FP elements in a vector to memory using qword indices.
  | VSCATTERQD = 1335
  /// Scatter packed double with signed qword indices.
  | VSCATTERQPD = 1336
  /// Scatter packed single with signed qword indices.
  | VSCATTERQPS = 1337
  /// Scatter SP/DP FP elements in a vector to memory using qword indices.
  | VSCATTERQQ = 1338
  /// Shuffle 128-bit lanes of a vector with 32 bit granular conditional update.
  | VSHUFF32X4 = 1339
  /// Shuffle 128-bit lanes of a vector with 64 bit granular conditional update.
  | VSHUFF64X2 = 1340
  /// Shuffle 128-bit lanes of a vector with 32 bit granular conditional update.
  | VSHUFI32X4 = 1341
  /// Shuffle 128-bit lanes of a vector with 64 bit granular conditional update.
  | VSHUFI64X2 = 1342
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | VSHUFPD = 1343
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | VSHUFPS = 1344
  /// Compute packed square roots of packed double-precision FP values.
  | VSQRTPD = 1345
  /// Compute square roots of packed single-precision floating-point values.
  | VSQRTPS = 1346
  /// Compute scalar square root of scalar double-precision FP values.
  | VSQRTSD = 1347
  /// Compute square root of scalar single-precision floating-point values.
  | VSQRTSS = 1348
  /// Subtract Packed Double-Precision Floating-Point Values.
  | VSUBPD = 1349
  /// Subtract Packed Single-Precision Floating-Point Values.
  | VSUBPS = 1350
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | VSUBSD = 1351
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | VSUBSS = 1352
  /// Packed Bit Test.
  | VTESTPD = 1353
  /// Packed Bit Test.
  | VTESTPS = 1354
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | VUCOMISD = 1355
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | VUCOMISS = 1356
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | VUNPCKHPD = 1357
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | VUNPCKHPS = 1358
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | VUNPCKLPD = 1359
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | VUNPCKLPS = 1360
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | VXORPD = 1361
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | VXORPS = 1362
  /// Zero Upper Bits of YMM Registers.
  | VZEROUPPER = 1363
  /// Wait.
  | WAIT = 1364
  /// Write Back and Invalidate Cache.
  | WBINVD = 1365
  /// Write FS Segment Base.
  | WRFSBASE = 1366
  /// Write GS Segment Base.
  | WRGSBASE = 1367
  /// Write to Model Specific Register.
  | WRMSR = 1368
  /// Write Data to User Page Key Register.
  | WRPKRU = 1369
  /// Write to a shadow stack.
  | WRSSD = 1370
  /// Write to a shadow stack.
  | WRSSQ = 1371
  /// Write to a user mode shadow stack.
  | WRUSSD = 1372
  /// Write to a user mode shadow stack.
  | WRUSSQ = 1373
  /// Transactional Abort.
  | XABORT = 1374
  /// Prefix hint to the beginning of an HLE transaction region.
  | XACQUIRE = 1375
  /// Exchange and Add.
  | XADD = 1376
  /// Transactional Begin.
  | XBEGIN = 1377
  /// Exchange Register/Memory with Register.
  | XCHG = 1378
  /// Cipher Block Chaining.
  | XCRYPTCBC = 1379
  /// Cipher Feedback Mode.
  | XCRYPTCFB = 1380
  /// Counter Mode (ACE2).
  | XCRYPTCTR = 1381
  /// Electronic code book.
  | XCRYPTECB = 1382
  /// Output Feedback Mode.
  | XCRYPTOFB = 1383
  /// Transactional End.
  | XEND = 1384
  /// Value of Extended Control Register.
  | XGETBV = 1385
  /// Table lookup translation.
  | XLAT = 1386
  /// Table Look-up Translation.
  | XLATB = 1387
  /// Modular Multiplication.
  | XMODEXP = 1388
  /// Logical Exclusive OR.
  | XOR = 1389
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | XORPD = 1390
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | XORPS = 1391
  /// Prefix hint to the end of an HLE transaction region.
  | XRELEASE = 1392
  /// Random Number Generation.
  | XRNG2 = 1393
  /// Restore Processor Extended States.
  | XRSTOR = 1394
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS = 1395
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS64 = 1396
  /// Save Processor Extended States.
  | XSAVE = 1397
  /// Save processor extended states with compaction to memory.
  | XSAVEC = 1398
  /// Save processor extended states with compaction to memory.
  | XSAVEC64 = 1399
  /// Save Processor Extended States Optimized.
  | XSAVEOPT = 1400
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES = 1401
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES64 = 1402
  /// Set Extended Control Register.
  | XSETBV = 1403
  /// Hash Function SHA-1.
  | XSHA1 = 1404
  /// Hash Function SHA-256.
  | XSHA256 = 1405
  /// Hash Function SHA-384.
  | XSHA384 = 1406
  /// Hash Function SHA-512.
  | XSHA512 = 1407
  /// Store Available Random Bytes.
  | XSTORERNG = 1408
  /// Test If In Transactional Execution.
  | XTEST = 1409
  /// Invalid Opcode.
  | InvalOP = 1410

/// Provides functions to check properties of opcodes.
[<RequireQualifiedAccess>]
module internal Opcode =
  let isBranch = function
    | Opcode.CALLFar | Opcode.CALLNear
    | Opcode.JMPFar | Opcode.JMPNear
    | Opcode.RETFar | Opcode.RETFarImm | Opcode.RETNear | Opcode.RETNearImm
    | Opcode.JA | Opcode.JB | Opcode.JBE | Opcode.JCXZ | Opcode.JECXZ
    | Opcode.JG | Opcode.JL | Opcode.JLE | Opcode.JNB | Opcode.JNL | Opcode.JNO
    | Opcode.JNP | Opcode.JNS | Opcode.JNZ | Opcode.JO | Opcode.JP
    | Opcode.JRCXZ | Opcode.JS | Opcode.JZ | Opcode.LOOP | Opcode.LOOPE
    | Opcode.LOOPNE -> true
    | _ -> false

  let isCETInstr = function
    | Opcode.INCSSPD | Opcode.INCSSPQ | Opcode.RDSSPD | Opcode.RDSSPQ
    | Opcode.SAVEPREVSSP | Opcode.RSTORSSP | Opcode.WRSSD | Opcode.WRSSQ
    | Opcode.WRUSSD | Opcode.WRUSSQ | Opcode.SETSSBSY | Opcode.CLRSSBSY -> true
    | _ -> false
