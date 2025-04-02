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
/// Intel opcodes. This type should be generated using
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
  /// Convert Doubleword to Quadword.
  | CDQ = 54
  /// Convert Doubleword to Quadword.
  | CDQE = 55
  /// Clear AC Flag in EFLAGS Register.
  | CLAC = 56
  /// Clear Carry Flag.
  | CLC = 57
  /// Clear Direction Flag.
  | CLD = 58
  /// Flush Cache Line.
  | CLFLUSH = 59
  /// Flush Cache Line Optimized.
  | CLFLUSHOPT = 60
  /// Clear Interrupt Flag.
  | CLI = 61
  /// Clear busy bit in a supervisor shadow stack token.
  | CLRSSBSY = 62
  /// Clear Task-Switched Flag in CR0.
  | CLTS = 63
  /// Cache Line Write Back.
  | CLWB = 64
  /// Complement Carry Flag.
  | CMC = 65
  /// Conditional Move (Move if above (CF = 0 and ZF = 0)).
  | CMOVA = 66
  /// Conditional Move (Move if above or equal (CF = 0)).
  | CMOVAE = 67
  /// Conditional Move (Move if below (CF = 1)).
  | CMOVB = 68
  /// Conditional Move (Move if below or equal (CF = 1 or ZF = 1)).
  | CMOVBE = 69
  /// Conditional move if carry.
  | CMOVC = 70
  /// Conditional Move (Move if greater (ZF = 0 and SF = OF)).
  | CMOVG = 71
  /// Conditional Move (Move if greater or equal (SF = OF)).
  | CMOVGE = 72
  /// Conditional Move (Move if less (SF <> OF)).
  | CMOVL = 73
  /// Conditional Move (Move if less or equal (ZF = 1 or SF <> OF)).
  | CMOVLE = 74
  /// Conditional move if not carry.
  | CMOVNC = 75
  /// Conditional Move (Move if not overflow (OF = 0)).
  | CMOVNO = 76
  /// Conditional Move (Move if not parity (PF = 0)).
  | CMOVNP = 77
  /// Conditional Move (Move if not sign (SF = 0)).
  | CMOVNS = 78
  /// Conditional Move (Move if not zero (ZF = 0)).
  | CMOVNZ = 79
  /// Conditional Move (Move if overflow (OF = 1)).
  | CMOVO = 80
  /// Conditional Move (Move if parity (PF = 1)).
  | CMOVP = 81
  /// Conditional Move (Move if sign (SF = 1)).
  | CMOVS = 82
  /// Conditional Move (Move if zero (ZF = 1)).
  | CMOVZ = 83
  /// Compare Two Operands.
  | CMP = 84
  /// Compare packed double-precision floating-point values.
  | CMPPD = 85
  /// Compare packed single-precision floating-point values.
  | CMPPS = 86
  /// Compare String Operands (byte).
  | CMPSB = 87
  /// Compare String Operands (dword) or Compare scalar dbl-precision FP values.
  | CMPSD = 88
  /// Compare String Operands (quadword).
  | CMPSQ = 89
  /// Compare scalar single-precision floating-point values.
  | CMPSS = 90
  /// Compare String Operands (word).
  | CMPSW = 91
  /// Compare and Exchange.
  | CMPXCHG = 92
  /// Compare and Exchange Bytes.
  | CMPXCHG16B = 93
  /// Compare and Exchange Bytes.
  | CMPXCHG8B = 94
  /// Compare Scalar Ordered Double-Precision FP Values and Set EFLAGS.
  | COMISD = 95
  /// Compare Scalar Ordered Single-Precision FP Values and Set EFLAGS.
  | COMISS = 96
  /// CPU Identification.
  | CPUID = 97
  /// Convert Quadword to Octaword.
  | CQO = 98
  /// Accumulate CRC32 Value.
  | CRC32 = 99
  /// Convert Packed Dword Integers to Packed Double-Precision FP Values.
  | CVTDQ2PD = 100
  /// Convert Packed Dword Integers to Packed Single-Precision FP Values.
  | CVTDQ2PS = 101
  /// Convert Packed Double-Precision FP Values to Packed Dword Integers.
  | CVTPD2DQ = 102
  /// Convert Packed Double-Precision FP Values to Packed Dword Integers.
  | CVTPD2PI = 103
  /// Convert Packed Double-Precision FP Values to Packed Single-Precision FP.
  | CVTPD2PS = 104
  /// Convert Packed Dword Integers to Packed Double-Precision FP Values.
  | CVTPI2PD = 105
  /// Convert Packed Dword Integers to Packed Single-Precision FP Values.
  | CVTPI2PS = 106
  /// Convert Packed Single-Precision FP Values to Packed Dword Integers.
  | CVTPS2DQ = 107
  /// Convert Packed Single-Precision FP Values to Packed Double-Precision FP.
  | CVTPS2PD = 108
  /// Convert Packed Single-Precision FP Values to Packed Dword Integers.
  | CVTPS2PI = 109
  /// Convert Scalar Double-Precision FP Value to Integer.
  | CVTSD2SI = 110
  /// Convert Scalar Double-Precision FP Value to Scalar Single-Precision FP.
  | CVTSD2SS = 111
  /// Convert Dword Integer to Scalar Double-Precision FP Value.
  | CVTSI2SD = 112
  /// Convert Dword Integer to Scalar Single-Precision FP Value.
  | CVTSI2SS = 113
  /// Convert Scalar Single-Precision FP Value to Scalar Double-Precision FP.
  | CVTSS2SD = 114
  /// Convert Scalar Single-Precision FP Value to Dword Integer.
  | CVTSS2SI = 115
  /// Convert with Truncation Packed Double-Precision FP Values to Packed Dword.
  | CVTTPD2DQ = 116
  /// Convert with Truncation Packed Double-Precision FP Values to Packed Dword.
  | CVTTPD2PI = 117
  /// Convert with Truncation Packed Single-Precision FP Values to Packed Dword.
  | CVTTPS2DQ = 118
  /// Convert with Truncation Packed Single-Precision FP Values to Packed Dword.
  | CVTTPS2PI = 119
  /// Convert with Truncation Scalar Double-Precision FP Value to Signed.
  | CVTTSD2SI = 120
  /// Convert with Truncation Scalar Single-Precision FP Value to Dword Integer.
  | CVTTSS2SI = 121
  /// Convert Word to Doubleword.
  | CWD = 122
  /// Convert Word to Doubleword.
  | CWDE = 123
  /// Decimal Adjust AL after Addition.
  | DAA = 124
  /// Decimal Adjust AL after Subtraction.
  | DAS = 125
  /// Decrement by 1.
  | DEC = 126
  /// Unsigned Divide.
  | DIV = 127
  /// Divide Packed Double-Precision Floating-Point Values.
  | DIVPD = 128
  /// Divide Packed Single-Precision Floating-Point Values.
  | DIVPS = 129
  /// Divide Scalar Double-Precision Floating-Point Values.
  | DIVSD = 130
  /// Divide Scalar Single-Precision Floating-Point Values.
  | DIVSS = 131
  /// Perform double-precision dot product for up to 2 elements and broadcast.
  | DPPD = 132
  /// Perform single-precision dot products for up to 4 elements and broadcast.
  | DPPS = 133
  /// Empty MMX Technology State.
  | EMMS = 134
  /// Execute an Enclave System Function of Specified Leaf Number.
  | ENCLS = 135
  /// Execute an Enclave User Function of Specified Leaf Number.
  | ENCLU = 136
  /// Terminate an Indirect Branch in 32-bit and Compatibility Mode.
  | ENDBR32 = 137
  /// Terminate an Indirect Branch in 64-bit Mode.
  | ENDBR64 = 138
  /// Make Stack Frame for Procedure Parameters.
  | ENTER = 139
  /// Extract Packed Floating-Point Values.
  | EXTRACTPS = 140
  /// Extract Field from Register.
  | EXTRQ = 141
  /// Compute 2x-1.
  | F2XM1 = 142
  /// Absolute Value.
  | FABS = 143
  /// Add.
  | FADD = 144
  /// Add and pop the register stack.
  | FADDP = 145
  /// Load Binary Coded Decimal.
  | FBLD = 146
  /// Store BCD Integer and Pop.
  | FBSTP = 147
  /// Change Sign.
  | FCHS = 148
  /// Clear Exceptions.
  | FCLEX = 149
  /// Floating-Point Conditional Move (if below (CF = 1)).
  | FCMOVB = 150
  /// Floating-Point Conditional Move (if below or equal (CF = 1 or ZF = 1)).
  | FCMOVBE = 151
  /// Floating-Point Conditional Move (if equal (ZF = 1)).
  | FCMOVE = 152
  /// Floating-Point Conditional Move (if not below (CF = 0)).
  | FCMOVNB = 153
  /// FP Conditional Move (if not below or equal (CF = 0 and ZF = 0)).
  | FCMOVNBE = 154
  /// Floating-Point Conditional Move (if not equal (ZF = 0)).
  | FCMOVNE = 155
  /// Floating-Point Conditional Move (if not unordered (PF = 0)).
  | FCMOVNU = 156
  /// Floating-Point Conditional Move (if unordered (PF = 1)).
  | FCMOVU = 157
  /// Compare Floating Point Values.
  | FCOM = 158
  /// Compare Floating Point Values and Set EFLAGS.
  | FCOMI = 159
  /// Compare Floating Point Values and Set EFLAGS.
  | FCOMIP = 160
  /// Compare Floating Point Values and pop register stack.
  | FCOMP = 161
  /// Compare Floating Point Values and pop register stack twice.
  | FCOMPP = 162
  /// Cosine.
  | FCOS = 163
  /// Decrement Stack-Top Pointer.
  | FDECSTP = 164
  /// Divide.
  | FDIV = 165
  /// Divide and pop the register stack.
  | FDIVP = 166
  /// Reverse Divide.
  | FDIVR = 167
  /// Reverse Divide and pop the register stack.
  | FDIVRP = 168
  /// Free Floating-Point Register.
  | FFREE = 169
  /// Performs FFREE ST(i) and pop stack.
  | FFREEP = 170
  /// Add.
  | FIADD = 171
  /// Compare Integer.
  | FICOM = 172
  /// Compare Integer and pop the register stack.
  | FICOMP = 173
  /// Divide.
  | FIDIV = 174
  /// Reverse Divide.
  | FIDIVR = 175
  /// Load Integer.
  | FILD = 176
  /// Multiply.
  | FIMUL = 177
  /// Increment Stack-Top Pointer.
  | FINCSTP = 178
  /// Initialize Floating-Point Unit.
  | FINIT = 179
  /// Store Integer.
  | FIST = 180
  /// Store Integer and pop the register stack.
  | FISTP = 181
  /// Store Integer with Truncation.
  | FISTTP = 182
  /// Subtract.
  | FISUB = 183
  /// Reverse Subtract.
  | FISUBR = 184
  /// Load Floating Point Value.
  | FLD = 185
  /// Load Constant (Push +1.0 onto the FPU register stack).
  | FLD1 = 186
  /// Load x87 FPU Control Word.
  | FLDCW = 187
  /// Load x87 FPU Environment.
  | FLDENV = 188
  /// Load Constant (Push log2e onto the FPU register stack).
  | FLDL2E = 189
  /// Load Constant (Push log210 onto the FPU register stack).
  | FLDL2T = 190
  /// Load Constant (Push log102 onto the FPU register stack).
  | FLDLG2 = 191
  /// Load Constant (Push loge2 onto the FPU register stack).
  | FLDLN2 = 192
  /// Load Constant (Push Pi onto the FPU register stack).
  | FLDPI = 193
  /// Load Constant (Push +0.0 onto the FPU register stack).
  | FLDZ = 194
  /// Multiply.
  | FMUL = 195
  /// Multiply and pop the register stack.
  | FMULP = 196
  /// Clear FP exception flags without checking for error conditions.
  | FNCLEX = 197
  /// Initialize FPU without checking error conditions.
  | FNINIT = 198
  /// No Operation.
  | FNOP = 199
  /// Save FPU state without checking error conditions.
  | FNSAVE = 200
  /// Store x87 FPU Control Word.
  | FNSTCW = 201
  /// Store FPU environment without checking error conditions.
  | FNSTENV = 202
  /// Store FPU status word without checking error conditions.
  | FNSTSW = 203
  /// Partial Arctangent.
  | FPATAN = 204
  /// Partial Remainder.
  | FPREM = 205
  /// Partial Remainder.
  | FPREM1 = 206
  /// Partial Tangent.
  | FPTAN = 207
  /// Round to Integer.
  | FRNDINT = 208
  /// Restore x87 FPU State.
  | FRSTOR = 209
  /// Store x87 FPU State.
  | FSAVE = 210
  /// Scale.
  | FSCALE = 211
  /// Sine.
  | FSIN = 212
  /// Sine and Cosine.
  | FSINCOS = 213
  /// Square Root.
  | FSQRT = 214
  /// Store Floating Point Value.
  | FST = 215
  /// Store FPU control word after checking error conditions.
  | FSTCW = 216
  /// Store x87 FPU Environment.
  | FSTENV = 217
  /// Store Floating Point Value.
  | FSTP = 218
  /// Store x87 FPU Status Word.
  | FSTSW = 219
  /// Subtract.
  | FSUB = 220
  /// Subtract and pop register stack.
  | FSUBP = 221
  /// Reverse Subtract.
  | FSUBR = 222
  /// Reverse Subtract and pop register stack.
  | FSUBRP = 223
  /// TEST.
  | FTST = 224
  /// Unordered Compare Floating Point Values.
  | FUCOM = 225
  /// Compare Floating Point Values and Set EFLAGS.
  | FUCOMI = 226
  /// Compare Floating Point Values and Set EFLAGS and pop register stack.
  | FUCOMIP = 227
  /// Unordered Compare Floating Point Values.
  | FUCOMP = 228
  /// Unordered Compare Floating Point Values.
  | FUCOMPP = 229
  /// Wait for FPU.
  | FWAIT = 230
  /// Examine ModR/M.
  | FXAM = 231
  /// Exchange Register Contents.
  | FXCH = 232
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR = 233
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR64 = 234
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE = 235
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE64 = 236
  /// Extract Exponent and Significand.
  | FXTRACT = 237
  /// compute y * log2x.
  | FYL2X = 238
  /// compute y * log2(x+1).
  | FYL2XP1 = 239
  /// GETSEC.
  | GETSEC = 240
  /// Galois Field Affine Transformation Inverse.
  | GF2P8AFFINEINVQB = 241
  /// Galois Field Affine Transformation.
  | GF2P8AFFINEQB = 242
  /// Galois Field Multiply Bytes.
  | GF2P8MULB = 243
  /// Packed Double-FP Horizontal Add.
  | HADDPD = 244
  /// Packed Single-FP Horizontal Add.
  | HADDPS = 245
  /// Halt.
  | HLT = 246
  /// Packed Double-FP Horizontal Subtract.
  | HSUBPD = 247
  /// Packed Single-FP Horizontal Subtract.
  | HSUBPS = 248
  /// Signed Divide.
  | IDIV = 249
  /// Signed Multiply.
  | IMUL = 250
  /// Input from Port.
  | IN = 251
  /// Increment by 1.
  | INC = 252
  /// Increment the shadow stack pointer (SSP).
  | INCSSPD = 253
  /// Increment the shadow stack pointer (SSP).
  | INCSSPQ = 254
  /// Input from Port to String.
  | INS = 255
  /// Input from Port to String (byte).
  | INSB = 256
  /// Input from Port to String (doubleword).
  | INSD = 257
  /// Insert Scalar Single-Precision Floating-Point Value.
  | INSERTPS = 258
  /// Inserts Field from a source Register to a destination Register.
  | INSERTQ = 259
  /// Input from Port to String (word).
  | INSW = 260
  /// Call to Interrupt (Interrupt vector specified by immediate byte).
  | INT = 261
  /// Call to Interrupt Procedure (Debug trap).
  | INT1 = 262
  /// Call to Interrupt (Interrupt 3-trap to debugger).
  | INT3 = 263
  /// Call to Interrupt (InteInterrupt 4-if overflow flag is 1).
  | INTO = 264
  /// Invalidate Internal Caches.
  | INVD = 265
  /// Invalidate Translations Derived from EPT.
  | INVEPT = 266
  /// Invalidate TLB Entries.
  | INVLPG = 267
  /// Invalidate Process-Context Identifier.
  | INVPCID = 268
  /// Invalidate Translations Based on VPID.
  | INVVPID = 269
  /// Return from interrupt.
  | IRET = 270
  /// Interrupt return (32-bit operand size).
  | IRETD = 271
  /// Interrupt return (64-bit operand size).
  | IRETQ = 272
  /// Interrupt return (16-bit operand size).
  | IRETW = 273
  /// Jump if Condition Is Met (Jump near if not below, CF = 0).
  | JAE = 274
  | JNC = 274
  | JNB = 274
  /// Jump if Condition Is Met (Jump short if below, CF = 1).
  | JC = 275
  | JNAE = 275
  | JB = 275
  /// Jump if Condition Is Met (Jump short if CX register is 0).
  | JCXZ = 276
  /// Jump if Condition Is Met (Jump short if ECX register is 0).
  | JECXZ = 277
  /// Jump if Condition Is Met (Jump near if not less, SF = OF).
  | JGE = 278
  | JNL = 278
  /// Far jmp.
  | JMPFar = 279
  /// Near jmp.
  | JMPNear = 280
  /// Jump if Condition Is Met (Jump short if below or equal, CF = 1 or ZF).
  | JNA = 281
  | JBE = 281
  /// Jump if Condition Is Met (Jump short if above, CF = 0 and ZF = 0).
  | JNBE = 282
  | JA = 282
  /// Jump if Cond Is Met (Jump short if less or equal, ZF = 1 or SF <> OF).
  | JNG = 283
  | JLE = 283
  /// Jump if Condition Is Met (Jump short if less, SF <> OF).
  | JNGE = 284
  | JL = 284
  /// Jump if Condition Is Met (Jump short if greater, ZF = 0 and SF = OF).
  | JNLE = 285
  | JG = 285
  /// Jump if Condition Is Met (Jump near if not overflow, OF = 0).
  | JNO = 286
  /// Jump if Condition Is Met (Jump near if not sign, SF = 0).
  | JNS = 287
  /// Jump if Condition Is Met (Jump near if not zero, ZF = 0).
  | JNZ = 288
  | JNE = 288
  /// Jump if Condition Is Met (Jump near if overflow, OF = 1).
  | JO = 289
  /// Jump if Condition Is Met (Jump near if parity, PF = 1).
  | JP = 290
  | JPE = 290
  /// Jump if Condition Is Met (Jump near if not parity, PF = 0).
  | JPO = 291
  | JNP = 291
  /// Jump if Condition Is Met (Jump short if RCX register is 0).
  | JRCXZ = 292
  /// Jump if Condition Is Met (Jump short if sign, SF = 1).
  | JS = 293
  /// Jump if Condition Is Met (Jump short if zero, ZF = 1).
  | JZ = 294
  | JE = 294
  /// Add two 8-bit opmasks.
  | KADDB = 295
  /// Add two 32-bit opmasks.
  | KADDD = 296
  /// Add two 64-bit opmasks.
  | KADDQ = 297
  /// Add two 16-bit opmasks.
  | KADDW = 298
  /// Logical AND two 8-bit opmasks.
  | KANDB = 299
  /// Logical AND two 32-bit opmasks.
  | KANDD = 300
  /// Logical AND NOT two 8-bit opmasks.
  | KANDNB = 301
  /// Logical AND NOT two 32-bit opmasks.
  | KANDND = 302
  /// Logical AND NOT two 64-bit opmasks.
  | KANDNQ = 303
  /// Logical AND NOT two 16-bit opmasks.
  | KANDNW = 304
  /// Logical AND two 64-bit opmasks.
  | KANDQ = 305
  /// Logical AND two 16-bit opmasks.
  | KANDW = 306
  /// Move from or move to opmask register of 8-bit data.
  | KMOVB = 307
  /// Move from or move to opmask register of 32-bit data.
  | KMOVD = 308
  /// Move from or move to opmask register of 64-bit data.
  | KMOVQ = 309
  /// Move from or move to opmask register of 16-bit data.
  | KMOVW = 310
  /// Bitwise NOT of two 8-bit opmasks.
  | KNOTB = 311
  /// Bitwise NOT of two 32-bit opmasks.
  | KNOTD = 312
  /// Bitwise NOT of two 64-bit opmasks.
  | KNOTQ = 313
  /// Bitwise NOT of two 16-bit opmasks.
  | KNOTW = 314
  /// Logical OR two 8-bit opmasks.
  | KORB = 315
  /// Logical OR two 32-bit opmasks.
  | KORD = 316
  /// Logical OR two 64-bit opmasks.
  | KORQ = 317
  /// Update EFLAGS according to the result of bitwise OR of two 8-bit opmasks.
  | KORTESTB = 318
  /// Update EFLAGS according to the result of bitwise OR of two 32-bit opmasks.
  | KORTESTD = 319
  /// Update EFLAGS according to the result of bitwise OR of two 64-bit opmasks.
  | KORTESTQ = 320
  /// Update EFLAGS according to the result of bitwise OR of two 16-bit opmasks.
  | KORTESTW = 321
  /// Logical OR two 16-bit opmasks.
  | KORW = 322
  /// Shift left 8-bitopmask by specified count.
  | KSHIFTLB = 323
  /// Shift left 32-bitopmask by specified count.
  | KSHIFTLD = 324
  /// Shift left 64-bitopmask by specified count.
  | KSHIFTLQ = 325
  /// Shift left 16-bitopmask by specified count.
  | KSHIFTLW = 326
  /// Shift right 8-bit opmask by specified count.
  | KSHIFTRB = 327
  /// Shift right 32-bit opmask by specified count.
  | KSHIFTRD = 328
  /// Shift right 64-bit opmask by specified count.
  | KSHIFTRQ = 329
  /// Shift right 16-bit opmask by specified count.
  | KSHIFTRW = 330
  /// Update EFLAGS according to result of bitwise TEST of two 8-bit opmasks.
  | KTESTB = 331
  /// Update EFLAGS according to result of bitwise TEST of two 32-bit opmasks.
  | KTESTD = 332
  /// Update EFLAGS according to result of bitwise TEST of two 64-bit opmasks.
  | KTESTQ = 333
  /// Update EFLAGS according to result of bitwise TEST of two 16-bit opmasks.
  | KTESTW = 334
  /// Unpack and interleave two 8-bit opmasks into 16-bit mask.
  | KUNPCKBW = 335
  /// Unpack and interleave two 32-bit opmasks into 64-bit mask.
  | KUNPCKDQ = 336
  /// Unpack and interleave two 16-bit opmasks into 32-bit mask.
  | KUNPCKWD = 337
  /// Bitwise logical XNOR of two 8-bit opmasks.
  | KXNORB = 338
  /// Bitwise logical XNOR of two 32-bit opmasks.
  | KXNORD = 339
  /// Bitwise logical XNOR of two 64-bit opmasks.
  | KXNORQ = 340
  /// Bitwise logical XNOR of two 16-bit opmasks.
  | KXNORW = 341
  /// Logical XOR of two 8-bit opmasks.
  | KXORB = 342
  /// Logical XOR of two 32-bit opmasks.
  | KXORD = 343
  /// Logical XOR of two 64-bit opmasks.
  | KXORQ = 344
  /// Logical XOR of two 16-bit opmasks.
  | KXORW = 345
  /// Load Status Flags into AH Register.
  | LAHF = 346
  /// Load Access Rights Byte.
  | LAR = 347
  /// Load Unaligned Integer 128 Bits.
  | LDDQU = 348
  /// Load MXCSR Register.
  | LDMXCSR = 349
  /// Load Far Pointer (DS).
  | LDS = 350
  /// Load Effective Address.
  | LEA = 351
  /// High Level Procedure Exit.
  | LEAVE = 352
  /// Load Far Pointer (ES).
  | LES = 353
  /// Load Fence.
  | LFENCE = 354
  /// Load Far Pointer (FS).
  | LFS = 355
  /// Load GlobalDescriptor Table Register.
  | LGDT = 356
  /// Load Far Pointer (GS).
  | LGS = 357
  /// Load Interrupt Descriptor Table Register.
  | LIDT = 358
  /// Load Local Descriptor Table Register.
  | LLDT = 359
  /// Load Machine Status Word.
  | LMSW = 360
  /// Assert LOCK# Signal Prefix.
  | LOCK = 361
  /// Load String (byte).
  | LODSB = 362
  /// Load String (doubleword).
  | LODSD = 363
  /// Load String (quadword).
  | LODSQ = 364
  /// Load String (word).
  | LODSW = 365
  /// Loop According to ECX Counter (count <> 0).
  | LOOP = 366
  /// Loop According to ECX Counter (count <> 0 and ZF = 1).
  | LOOPE = 367
  /// Loop According to ECX Counter (count <> 0 and ZF = 0).
  | LOOPNE = 368
  /// Load Segment Limit.
  | LSL = 369
  /// Load Far Pointer (SS).
  | LSS = 370
  /// Load Task Register.
  | LTR = 371
  /// the Number of Leading Zero Bits.
  | LZCNT = 372
  /// Store Selected Bytes of Double Quadword.
  | MASKMOVDQU = 373
  /// Store Selected Bytes of Quadword.
  | MASKMOVQ = 374
  /// Return Maximum Packed Double-Precision Floating-Point Values.
  | MAXPD = 375
  /// Return Maximum Packed Single-Precision Floating-Point Values.
  | MAXPS = 376
  /// Return Maximum Scalar Double-Precision Floating-Point Values.
  | MAXSD = 377
  /// Return Maximum Scalar Single-Precision Floating-Point Values.
  | MAXSS = 378
  /// Memory Fence.
  | MFENCE = 379
  /// Return Minimum Packed Double-Precision Floating-Point Values.
  | MINPD = 380
  /// Return Minimum Packed Single-Precision Floating-Point Values.
  | MINPS = 381
  /// Return Minimum Scalar Double-Precision Floating-Point Values.
  | MINSD = 382
  /// Return Minimum Scalar Single-Precision Floating-Point Values.
  | MINSS = 383
  /// Set Up Monitor Address.
  | MONITOR = 384
  /// MOV.
  | MOV = 385
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | MOVAPD = 386
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | MOVAPS = 387
  /// Move Data After Swapping Bytes.
  | MOVBE = 388
  /// Move Doubleword.
  | MOVD = 389
  /// Move One Double-FP and Duplicate.
  | MOVDDUP = 390
  /// Move Quadword from XMM to MMX Technology Register.
  | MOVDQ2Q = 391
  /// Move Aligned Double Quadword.
  | MOVDQA = 392
  /// Move Unaligned Double Quadword.
  | MOVDQU = 393
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | MOVHLPS = 394
  /// Move High Packed Double-Precision Floating-Point Value.
  | MOVHPD = 395
  /// Move High Packed Single-Precision Floating-Point Values.
  | MOVHPS = 396
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | MOVLHPS = 397
  /// Move Low Packed Double-Precision Floating-Point Value.
  | MOVLPD = 398
  /// Move Low Packed Single-Precision Floating-Point Values.
  | MOVLPS = 399
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | MOVMSKPD = 400
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | MOVMSKPS = 401
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQ = 402
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQA = 403
  /// Store Doubleword Using Non-Temporal Hint.
  | MOVNTI = 404
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPD = 405
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPS = 406
  /// Store of Quadword Using Non-Temporal Hint.
  | MOVNTQ = 407
  /// Move Quadword.
  | MOVQ = 408
  /// Move Quadword from MMX Technology to XMM Register.
  | MOVQ2DQ = 409
  /// Move Data from String to String (byte).
  | MOVSB = 410
  /// Move Data from String to String (doubleword).
  | MOVSD = 411
  /// Move Packed Single-FP High and Duplicate.
  | MOVSHDUP = 412
  /// Move Packed Single-FP Low and Duplicate.
  | MOVSLDUP = 413
  /// Move Data from String to String (quadword).
  | MOVSQ = 414
  /// Move Scalar Single-Precision Floating-Point Values.
  | MOVSS = 415
  /// Move Data from String to String (word).
  | MOVSW = 416
  /// Move with Sign-Extension.
  | MOVSX = 417
  /// Move with Sign-Extension (doubleword to quadword).
  | MOVSXD = 418
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | MOVUPD = 419
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | MOVUPS = 420
  /// Move with Zero-Extend.
  | MOVZX = 421
  /// Compute Multiple Packed Sums of Absolute Difference.
  | MPSADBW = 422
  /// Unsigned Multiply.
  | MUL = 423
  /// Multiply Packed Double-Precision Floating-Point Values.
  | MULPD = 424
  /// Multiply Packed Single-Precision Floating-Point Values.
  | MULPS = 425
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | MULSD = 426
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | MULSS = 427
  /// Unsigned multiply without affecting arithmetic flags.
  | MULX = 428
  /// Monitor Wait.
  | MWAIT = 429
  /// Two's Complement Negation.
  | NEG = 430
  /// No Operation.
  | NOP = 431
  /// One's Complement Negation.
  | NOT = 432
  /// Logical Inclusive OR.
  | OR = 433
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | ORPD = 434
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | ORPS = 435
  /// Output to Port.
  | OUT = 436
  /// Output String to Port.
  | OUTS = 437
  /// Output String to Port (byte).
  | OUTSB = 438
  /// Output String to Port (doubleword).
  | OUTSD = 439
  /// Output String to Port (word).
  | OUTSW = 440
  /// Computes the absolute value of each signed byte data element.
  | PABSB = 441
  /// Computes the absolute value of each signed 32-bit data element.
  | PABSD = 442
  /// Computes the absolute value of each signed 16-bit data element.
  | PABSW = 443
  /// Pack with Signed Saturation.
  | PACKSSDW = 444
  /// Pack with Signed Saturation.
  | PACKSSWB = 445
  /// Pack with Unsigned Saturation.
  | PACKUSDW = 446
  /// Pack with Unsigned Saturation.
  | PACKUSWB = 447
  /// Add Packed byte Integers.
  | PADDB = 448
  /// Add Packed Doubleword Integers.
  | PADDD = 449
  /// Add Packed Quadword Integers.
  | PADDQ = 450
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | PADDSB = 451
  /// Add Packed Signed Integers with Signed Saturation (word).
  | PADDSW = 452
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | PADDUSB = 453
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | PADDUSW = 454
  /// Add Packed word Integers.
  | PADDW = 455
  /// Packed Align Right.
  | PALIGNR = 456
  /// Logical AND.
  | PAND = 457
  /// Logical AND NOT.
  | PANDN = 458
  /// Spin Loop Hint.
  | PAUSE = 459
  /// Average Packed Integers (byte).
  | PAVGB = 460
  /// Average Packed Integers (word).
  | PAVGW = 461
  /// Variable Blend Packed Bytes.
  | PBLENDVB = 462
  /// Blend Packed Words.
  | PBLENDW = 463
  /// Perform carryless multiplication of two 64-bit numbers.
  | PCLMULQDQ = 464
  /// Compare Packed Data for Equal (byte).
  | PCMPEQB = 465
  /// Compare Packed Data for Equal (doubleword).
  | PCMPEQD = 466
  /// Compare Packed Data for Equal (quadword).
  | PCMPEQQ = 467
  /// Compare packed words for equal.
  | PCMPEQW = 468
  /// Packed Compare Explicit Length Strings, Return Index.
  | PCMPESTRI = 469
  /// Packed Compare Explicit Length Strings, Return Mask.
  | PCMPESTRM = 470
  /// Compare Packed Signed Integers for Greater Than (byte).
  | PCMPGTB = 471
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | PCMPGTD = 472
  /// Performs logical compare of greater-than on packed integer quadwords.
  | PCMPGTQ = 473
  /// Compare Packed Signed Integers for Greater Than (word).
  | PCMPGTW = 474
  /// Packed Compare Implicit Length Strings, Return Index.
  | PCMPISTRI = 475
  /// Packed Compare Implicit Length Strings, Return Mask.
  | PCMPISTRM = 476
  /// Parallel deposit of bits using a mask.
  | PDEP = 477
  /// Parallel extraction of bits using a mask.
  | PEXT = 478
  /// Extract Byte.
  | PEXTRB = 479
  /// Extract Dword.
  | PEXTRD = 480
  /// Extract Qword.
  | PEXTRQ = 481
  /// Extract Word.
  | PEXTRW = 482
  /// Packed Horizontal Add.
  | PHADDD = 483
  /// Packed Horizontal Add and Saturate.
  | PHADDSW = 484
  /// Packed Horizontal Add.
  | PHADDW = 485
  /// Packed Horizontal Word Minimum.
  | PHMINPOSUW = 486
  /// Packed Horizontal Subtract.
  | PHSUBD = 487
  /// Packed Horizontal Subtract and Saturate.
  | PHSUBSW = 488
  /// Packed Horizontal Subtract.
  | PHSUBW = 489
  /// Insert Byte.
  | PINSRB = 490
  /// Insert a dword value from 32-bit register or memory into an XMM register.
  | PINSRD = 491
  /// Insert a qword value from 64-bit register or memory into an XMM register.
  | PINSRQ = 492
  /// Insert Word.
  | PINSRW = 493
  /// Multiply and Add Packed Signed and Unsigned Bytes.
  | PMADDUBSW = 494
  /// Multiply and Add Packed Integers.
  | PMADDWD = 495
  /// Compare packed signed byte integers.
  | PMAXSB = 496
  /// Compare packed signed dword integers.
  | PMAXSD = 497
  /// Maximum of Packed Signed Word Integers.
  | PMAXSW = 498
  /// Maximum of Packed Unsigned Byte Integers.
  | PMAXUB = 499
  /// Compare packed unsigned dword integers.
  | PMAXUD = 500
  /// Compare packed unsigned word integers.
  | PMAXUW = 501
  /// Minimum of Packed Signed Byte Integers.
  | PMINSB = 502
  /// Compare packed signed dword integers.
  | PMINSD = 503
  /// Minimum of Packed Signed Word Integers.
  | PMINSW = 504
  /// Minimum of Packed Unsigned Byte Integers.
  | PMINUB = 505
  /// Minimum of Packed Dword Integers.
  | PMINUD = 506
  /// Compare packed unsigned word integers.
  | PMINUW = 507
  /// Move Byte Mask.
  | PMOVMSKB = 508
  /// Packed Move with Sign Extend.
  | PMOVSXBD = 509
  /// Packed Move with Sign Extend.
  | PMOVSXBQ = 510
  /// Packed Move with Sign Extend.
  | PMOVSXBW = 511
  /// Packed Move with Sign Extend.
  | PMOVSXDQ = 512
  /// Packed Move with Sign Extend.
  | PMOVSXWD = 513
  /// Packed Move with Sign Extend.
  | PMOVSXWQ = 514
  /// Packed Move with Zero Extend.
  | PMOVZXBD = 515
  /// Packed Move with Zero Extend.
  | PMOVZXBQ = 516
  /// Packed Move with Zero Extend.
  | PMOVZXBW = 517
  /// Packed Move with Zero Extend.
  | PMOVZXDQ = 518
  /// Packed Move with Zero Extend.
  | PMOVZXWD = 519
  /// Packed Move with Zero Extend.
  | PMOVZXWQ = 520
  /// Multiply Packed Doubleword Integers.
  | PMULDQ = 521
  /// Packed Multiply High with Round and Scale.
  | PMULHRSW = 522
  /// Multiply Packed Unsigned Integers and Store High Result.
  | PMULHUW = 523
  /// Multiply Packed Signed Integers and Store High Result.
  | PMULHW = 524
  /// Multiply Packed Integers and Store Low Result.
  | PMULLD = 525
  /// Multiply Packed Signed Integers and Store Low Result.
  | PMULLW = 526
  /// Multiply Packed Unsigned Doubleword Integers.
  | PMULUDQ = 527
  /// Pop a Value from the Stack.
  | POP = 528
  /// Pop All General-Purpose Registers (word).
  | POPA = 529
  /// Pop All General-Purpose Registers (doubleword).
  | POPAD = 530
  /// Return the Count of Number of Bits Set to 1.
  | POPCNT = 531
  /// Pop Stack into EFLAGS Register (lower 16bits EFLAGS).
  | POPF = 532
  /// Pop Stack into EFLAGS Register (EFLAGS).
  | POPFD = 533
  /// Pop Stack into EFLAGS Register (RFLAGS).
  | POPFQ = 534
  /// Bitwise Logical OR.
  | POR = 535
  /// Prefetch Data Into Caches (using NTA hint).
  | PREFETCHNTA = 536
  /// Prefetch Data Into Caches (using T0 hint).
  | PREFETCHT0 = 537
  /// Prefetch Data Into Caches (using T1 hint).
  | PREFETCHT1 = 538
  /// Prefetch Data Into Caches (using T2 hint).
  | PREFETCHT2 = 539
  /// Prefetch Data into Caches in Anticipation of a Write.
  | PREFETCHW = 540
  /// Prefetch Vector Data Into Caches with Intent to Write and T1 Hint.
  | PREFETCHWT1 = 541
  /// Compute Sum of Absolute Differences.
  | PSADBW = 542
  /// Packed Shuffle Bytes.
  | PSHUFB = 543
  /// Shuffle Packed Doublewords.
  | PSHUFD = 544
  /// Shuffle Packed High Words.
  | PSHUFHW = 545
  /// Shuffle Packed Low Words.
  | PSHUFLW = 546
  /// Shuffle Packed Words.
  | PSHUFW = 547
  /// Packed Sign Byte.
  | PSIGNB = 548
  /// Packed Sign Doubleword.
  | PSIGND = 549
  /// Packed Sign Word.
  | PSIGNW = 550
  /// Shift Packed Data Left Logical (doubleword).
  | PSLLD = 551
  /// Shift Double Quadword Left Logical.
  | PSLLDQ = 552
  /// Shift Packed Data Left Logical (quadword).
  | PSLLQ = 553
  /// Shift Packed Data Left Logical (word).
  | PSLLW = 554
  /// Shift Packed Data Right Arithmetic (doubleword).
  | PSRAD = 555
  /// Shift Packed Data Right Arithmetic (word).
  | PSRAW = 556
  /// Shift Packed Data Right Logical (doubleword).
  | PSRLD = 557
  /// Shift Double Quadword Right Logical.
  | PSRLDQ = 558
  /// Shift Packed Data Right Logical (quadword).
  | PSRLQ = 559
  /// Shift Packed Data Right Logical (word).
  | PSRLW = 560
  /// Subtract Packed Integers (byte).
  | PSUBB = 561
  /// Subtract Packed Integers (doubleword).
  | PSUBD = 562
  /// Subtract Packed Integers (quadword).
  | PSUBQ = 563
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | PSUBSB = 564
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | PSUBSW = 565
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | PSUBUSB = 566
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | PSUBUSW = 567
  /// Subtract Packed Integers (word).
  | PSUBW = 568
  /// Logical Compare.
  | PTEST = 569
  /// Unpack High Data.
  | PUNPCKHBW = 570
  /// Unpack High Data.
  | PUNPCKHDQ = 571
  /// Unpack High Data.
  | PUNPCKHQDQ = 572
  /// Unpack High Data.
  | PUNPCKHWD = 573
  /// Unpack Low Data.
  | PUNPCKLBW = 574
  /// Unpack Low Data.
  | PUNPCKLDQ = 575
  /// Unpack Low Data.
  | PUNPCKLQDQ = 576
  /// Unpack Low Data.
  | PUNPCKLWD = 577
  /// Push Word, Doubleword or Quadword Onto the Stack.
  | PUSH = 578
  /// Push All General-Purpose Registers (word).
  | PUSHA = 579
  /// Push All General-Purpose Registers (doubleword).
  | PUSHAD = 580
  /// Push EFLAGS Register onto the Stack (16bits of EFLAGS).
  | PUSHF = 581
  /// Push EFLAGS Register onto the Stack (EFLAGS).
  | PUSHFD = 582
  /// Push EFLAGS Register onto the Stack (RFLAGS).
  | PUSHFQ = 583
  /// Logical Exclusive OR.
  | PXOR = 584
  /// Rotate x bits (CF, r/m(x)) left once.
  | RCL = 585
  /// Compute reciprocals of packed single-precision floating-point values.
  | RCPPS = 586
  /// Compute reciprocal of scalar single-precision floating-point values.
  | RCPSS = 587
  /// Rotate x bits (CF, r/m(x)) right once.
  | RCR = 588
  /// Read FS Segment Base.
  | RDFSBASE = 589
  /// Read GS Segment Base.
  | RDGSBASE = 590
  /// Read from Model Specific Register.
  | RDMSR = 591
  /// Read Protection Key Rights for User Pages.
  | RDPKRU = 592
  /// Read Performance-Monitoring Counters.
  | RDPMC = 593
  /// Read Random Number.
  | RDRAND = 594
  /// Read Random SEED.
  | RDSEED = 595
  /// Read shadow stack point (SSP).
  | RDSSPD = 596
  /// Read shadow stack point (SSP).
  | RDSSPQ = 597
  /// Read Time-Stamp Counter.
  | RDTSC = 598
  /// Read Time-Stamp Counter and Processor ID.
  | RDTSCP = 599
  /// Repeat while ECX not zero.
  | REP = 600
  /// Repeat while equal/Repeat while zero.
  | REPE = 601
  /// Repeat while not equal/Repeat while not zero.
  | REPNE = 602
  /// Repeat while not equal/Repeat while not zero.
  | REPNZ = 603
  /// Repeat while equal/Repeat while zero.
  | REPZ = 604
  /// Far return.
  | RETFar = 605
  /// Far return w/ immediate.
  | RETFarImm = 606
  /// Near return.
  | RETNear = 607
  /// Near return w/ immediate .
  | RETNearImm = 608
  /// Rotate x bits r/m(x) left once.
  | ROL = 609
  /// Rotate x bits r/m(x) right once.
  | ROR = 610
  /// Rotate right without affecting arithmetic flags.
  | RORX = 611
  /// Round Packed Double Precision Floating-Point Values.
  | ROUNDPD = 612
  /// Round Packed Single Precision Floating-Point Values.
  | ROUNDPS = 613
  /// Round Scalar Double Precision Floating-Point Values.
  | ROUNDSD = 614
  /// Round Scalar Single Precision Floating-Point Values.
  | ROUNDSS = 615
  /// Resume from System Management Mode.
  | RSM = 616
  /// Compute reciprocals of square roots of packed single-precision FP values.
  | RSQRTPS = 617
  /// Compute reciprocal of square root of scalar single-precision FP values.
  | RSQRTSS = 618
  /// Restore a shadow stack pointer (SSP).
  | RSTORSSP = 619
  /// Store AH into Flags.
  | SAHF = 620
  /// Shift.
  | SAR = 621
  /// Shift arithmetic right.
  | SARX = 622
  /// Save previous shadow stack pointer (SSP).
  | SAVEPREVSSP = 623
  /// Integer Subtraction with Borrow.
  | SBB = 624
  /// Scan String (byte).
  | SCASB = 625
  /// Scan String (doubleword).
  | SCASD = 626
  /// Scan String (quadword).
  | SCASQ = 627
  /// Scan String (word).
  | SCASW = 628
  /// Set byte if above (CF = 0 and ZF = 0).
  | SETA = 629
  /// Set byte if below (CF = 1).
  | SETB = 630
  /// Set byte if below or equal (CF = 1 or ZF = 1).
  | SETBE = 631
  /// Set byte if greater (ZF = 0 and SF = OF).
  | SETG = 632
  /// Set byte if less (SF <> OF).
  | SETL = 633
  /// Set byte if less or equal (ZF = 1 or SF <> OF).
  | SETLE = 634
  /// Set byte if not below (CF = 0).
  | SETNB = 635
  /// Set byte if not less (SF = OF).
  | SETNL = 636
  /// Set byte if not overflow (OF = 0).
  | SETNO = 637
  /// Set byte if not parity (PF = 0).
  | SETNP = 638
  /// Set byte if not sign (SF = 0).
  | SETNS = 639
  /// Set byte if not zero (ZF = 0).
  | SETNZ = 640
  /// Set byte if overflow (OF = 1).
  | SETO = 641
  /// Set byte if parity (PF = 1).
  | SETP = 642
  /// Set byte if sign (SF = 1).
  | SETS = 643
  /// Set busy bit in a supervisor shadow stack token.
  | SETSSBSY = 644
  /// Set byte if sign (ZF = 1).
  | SETZ = 645
  /// Store Fence.
  | SFENCE = 646
  /// Store Global Descriptor Table Register.
  | SGDT = 647
  /// Perform an Intermediate Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG1 = 648
  /// Perform a Final Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG2 = 649
  /// Calculate SHA1 state E after four rounds.
  | SHA1NEXTE = 650
  /// Perform four rounds of SHA1 operations.
  | SHA1RNDS4 = 651
  /// Perform an intermediate calculation for the next 4 SHA256 message dwords.
  | SHA256MSG1 = 652
  /// Perform the final calculation for the next four SHA256 message dwords.
  | SHA256MSG2 = 653
  /// Perform two rounds of SHA256 operations.
  | SHA256RNDS2 = 654
  /// Shift.
  | SHL = 655
  /// Double Precision Shift Left.
  | SHLD = 656
  /// Shift logic left.
  | SHLX = 657
  /// Shift.
  | SHR = 658
  /// Double Precision Shift Right.
  | SHRD = 659
  /// Shift logic right.
  | SHRX = 660
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | SHUFPD = 661
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | SHUFPS = 662
  /// Store Interrupt Descriptor Table Register.
  | SIDT = 663
  /// Store Local Descriptor Table Register.
  | SLDT = 664
  /// Store Machine Status Word.
  | SMSW = 665
  /// Compute packed square roots of packed double-precision FP values.
  | SQRTPD = 666
  /// Compute square roots of packed single-precision floating-point values.
  | SQRTPS = 667
  /// Compute scalar square root of scalar double-precision FP values.
  | SQRTSD = 668
  /// Compute square root of scalar single-precision floating-point values.
  | SQRTSS = 669
  /// Set AC Flag in EFLAGS Register.
  | STAC = 670
  /// Set Carry Flag.
  | STC = 671
  /// Set Direction Flag.
  | STD = 672
  /// Set Interrupt Flag.
  | STI = 673
  /// Store MXCSR Register State.
  | STMXCSR = 674
  /// Store String (store AL).
  | STOSB = 675
  /// Store String (store EAX).
  | STOSD = 676
  /// Store String (store RAX).
  | STOSQ = 677
  /// Store String (store AX).
  | STOSW = 678
  /// Store Task Register.
  | STR = 679
  /// Subtract.
  | SUB = 680
  /// Subtract Packed Double-Precision Floating-Point Values.
  | SUBPD = 681
  /// Subtract Packed Single-Precision Floating-Point Values.
  | SUBPS = 682
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | SUBSD = 683
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | SUBSS = 684
  /// Swap GS Base Register.
  | SWAPGS = 685
  /// Fast System Call.
  | SYSCALL = 686
  /// Fast System Call.
  | SYSENTER = 687
  /// Fast Return from Fast System Call.
  | SYSEXIT = 688
  /// Return From Fast System Call.
  | SYSRET = 689
  /// Logical Compare.
  | TEST = 690
  /// Count the Number of Trailing Zero Bits.
  | TZCNT = 691
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | UCOMISD = 692
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | UCOMISS = 693
  /// Undefined instruction (Raise invalid opcode exception).
  | UD0 = 694
  /// Undefined Instruction (Raise invalid opcode exception).
  | UD1 = 695
  /// Undefined Instruction (Raise invalid opcode exception).
  | UD2 = 696
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | UNPCKHPD = 697
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | UNPCKHPS = 698
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | UNPCKLPD = 699
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | UNPCKLPS = 700
  /// Packed Single-Precision Floating-Point Fused Multiply-Add.
  | V4FMADDPS = 701
  /// Scalar Single-Precision Floating-Point Fused Multiply-Add.
  | V4FMADDSS = 702
  /// Packed Single-Precision Floating-Point Fused Multiply-Add and Negate.
  | V4FNMADDPS = 703
  /// Scalar Single-Precision Floating-Point Fused Multiply-Add and Negate.
  | V4FNMADDSS = 704
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPD = 705
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPS = 706
  /// Add Scalar Double-Precision Floating-Point Values.
  | VADDSD = 707
  /// Add Scalar Single-Precision Floating-Point Values.
  | VADDSS = 708
  /// Packed Double-FP Add/Subtract.
  | VADDSUBPD = 709
  /// Packed Single-FP Add/Subtract.
  | VADDSUBPS = 710
  /// Perform One Round of an AES Decryption Flow.
  | VAESDEC = 711
  /// Perform Last Round of an AES Decryption Flow.
  | VAESDECLAST = 712
  /// Perform One Round of an AES Encryption Flow.
  | VAESENC = 713
  /// Perform Last Round of an AES Encryption Flow.
  | VAESENCLAST = 714
  /// Perform dword alignment of two concatenated source vectors.
  | VALIGND = 715
  /// Perform qword alignment of two concatenated source vectors.
  | VALIGNQ = 716
  /// Bitwise Logical AND of Packed Double-Precision Floating-Point Values.
  | VANDNPD = 717
  /// Bitwise Logical AND of Packed Single-Precision Floating-Point Values.
  | VANDNPS = 718
  /// Bitwise Logical AND NOT of Packed Double-Precision Floating-Point Values.
  | VANDPD = 719
  /// Bitwise Logical AND NOT of Packed Single-Precision Floating-Point Values.
  | VANDPS = 720
  /// Replace the VBLENDVPD instructions (using opmask as select control).
  | VBLENDMPD = 721
  /// Replace the VBLENDVPS instructions (using opmask as select control).
  | VBLENDMPS = 722
  /// Blend Packed Double-Precision Floats.
  | VBLENDPD = 723
  /// Blend Packed Single-Precision Floats.
  | VBLENDPS = 724
  /// Variable Blend Packed Double-Precision Floats.
  | VBLENDVPD = 725
  /// Variable Blend Packed Single-Precision Floats.
  | VBLENDVPS = 726
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTF128 = 727
  /// Broadcast 128 bits of int data in mem to low and high 128-bits in ymm1.
  | VBROADCASTI128 = 728
  /// Broadcast two dword elements.
  | VBROADCASTI32X2 = 729
  /// Broadcast four dword elements.
  | VBROADCASTI32X4 = 730
  /// Broadcast eight dword elements.
  | VBROADCASTI32X8 = 731
  /// Broadcast two qword elements.
  | VBROADCASTI64X2 = 732
  /// Broadcast four qword elements.
  | VBROADCASTI64X4 = 733
  /// Broadcast low double-precision floating-point element.
  | VBROADCASTSD = 734
  /// Broadcast Floating-Point Data.
  | VBROADCASTSS = 735
  /// Compare Packed Double-Precision Floating-Point Values.
  | VCMPPD = 736
  /// Compare Packed Single-Precision Floating-Point Values.
  | VCMPPS = 737
  /// Compare Scalar Double-Precision Floating-Point Values.
  | VCMPSD = 738
  /// Scalar Single-Precision Floating-Point Values.
  | VCMPSS = 739
  /// Compare Scalar Ordered Double-Precision FP Values and Set EFLAGS.
  | VCOMISD = 740
  /// Compare Scalar Ordered Single-Precision FP Values and Set EFLAGS.
  | VCOMISS = 741
  /// Compress packed DP elements of a vector.
  | VCOMPRESSPD = 742
  /// Compress packed SP elements of a vector.
  | VCOMPRESSPS = 743
  /// Convert two packed signed doubleword integers.
  | VCVTDQ2PD = 744
  /// Convert Packed Dword Integers to Packed Single-Precision FP Values.
  | VCVTDQ2PS = 745
  /// Convert Two Packed Single Data to One Packed BF16 Data.
  | VCVTNE2PS2BF16 = 746
  /// Convert Packed Single Data to Packed BF16 Data.
  | VCVTNEPS2BF16 = 747
  /// Convert Packed Double-Precision FP Values to Packed Doubleword Integers.
  | VCVTPD2DQ = 748
  /// Convert two packed double-precision floating-point values.
  | VCVTPD2PS = 749
  /// Convert Packed Double-Precision FP Values to Packed Quadword Integers.
  | VCVTPD2QQ = 750
  /// Convert Packed DP FP Values to Packed Unsigned DWord Integers.
  | VCVTPD2UDQ = 751
  /// Convert Packed DP FP Values to Packed Unsigned QWord Integers.
  | VCVTPD2UQQ = 752
  /// Convert 16-bit FP values to Single-Precision FP values.
  | VCVTPH2PS = 753
  /// Conv Packed Single-Precision FP Values to Packed Signed DWord Int Values.
  | VCVTPS2DQ = 754
  /// Conv Packed Single-Precision FP Values to Packed Dbl-Precision FP Values.
  | VCVTPS2PD = 755
  /// Convert Single-Precision FP value to 16-bit FP value.
  | VCVTPS2PH = 756
  /// Convert Packed SP FP Values to Packed Signed QWord Int Values.
  | VCVTPS2QQ = 757
  /// Convert Packed SP FP Values to Packed Unsigned DWord Int Values.
  | VCVTPS2UDQ = 758
  /// Convert Packed SP FP Values to Packed Unsigned QWord Int Values.
  | VCVTPS2UQQ = 759
  /// Convert Packed Quadword Integers to Packed Double-Precision FP Values.
  | VCVTQQ2PD = 760
  /// Convert Packed Quadword Integers to Packed Single-Precision FP Values.
  | VCVTQQ2PS = 761
  /// Convert Scalar Double-Precision FP Value to Integer.
  | VCVTSD2SI = 762
  /// Convert Scalar Double-Precision FP Val to Scalar Single-Precision FP Val.
  | VCVTSD2SS = 763
  /// Convert Scalar Double-Precision FP Value to Unsigned Doubleword Integer.
  | VCVTSD2USI = 764
  /// Convert Dword Integer to Scalar Double-Precision FP Value.
  | VCVTSI2SD = 765
  /// Convert Dword Integer to Scalar Single-Precision FP Value.
  | VCVTSI2SS = 766
  /// Convert Scalar Single-Precision FP Val to Scalar Double-Precision FP Val.
  | VCVTSS2SD = 767
  /// Convert Scalar Single-Precision FP Value to Dword Integer.
  | VCVTSS2SI = 768
  /// Convert Scalar Single-Precision FP Value to Unsigned Doubleword Integer.
  | VCVTSS2USI = 769
  /// Conv with Trunc Packed Double-Precision FP Val to Packed Dword Integers.
  | VCVTTPD2DQ = 770
  /// Convert with Truncation Packed DP FP Values to Packed QWord Integers.
  | VCVTTPD2QQ = 771
  /// Convert with Truncation Packed DP FP Values to Packed Unsigned DWord Int.
  | VCVTTPD2UDQ = 772
  /// Convert with Truncation Packed DP FP Values to Packed Unsigned QWord Int.
  | VCVTTPD2UQQ = 773
  /// Conv with Trunc Packed Single-Precision FP Val to Packed Dword Integers.
  | VCVTTPS2DQ = 774
  /// Convert with Truncation Packed SP FP Values to Packed Signed QWord Int.
  | VCVTTPS2QQ = 775
  /// Convert with Truncation Packed SP FP Values to Packed Unsigned DWord Int.
  | VCVTTPS2UDQ = 776
  /// Convert with Truncation Packed SP FP Values to Packed Unsigned QWord Int.
  | VCVTTPS2UQQ = 777
  /// Convert with Truncation Scalar Double-Precision FP Value to Signed.
  | VCVTTSD2SI = 778
  /// Convert with Truncation Scalar DP FP Value to Unsigned Integer.
  | VCVTTSD2USI = 779
  /// Convert with Truncation Scalar Single-Precision FP Value to Dword Integer.
  | VCVTTSS2SI = 780
  /// Convert with Truncation Scalar Single-Precision FP Value to Unsigned Int.
  | VCVTTSS2USI = 781
  /// Convert Packed Unsigned DWord Integers to Packed DP FP Values.
  | VCVTUDQ2PD = 782
  /// Convert Packed Unsigned DWord Integers to Packed SP FP Values.
  | VCVTUDQ2PS = 783
  /// Convert Packed Unsigned QWord Integers to Packed DP FP Values.
  | VCVTUQQ2PD = 784
  /// Convert Packed Unsigned QWord Integers to Packed SP FP Values.
  | VCVTUQQ2PS = 785
  /// Convert an signed integer to the low DP FP elem and merge to a vector.
  | VCVTUSI2SD = 786
  /// Convert an signed integer to the low SP FP elem and merge to a vector.
  | VCVTUSI2SS = 787
  /// Convert an unsigned integer to the low DP FP elem and merge to a vector.
  | VCVTUSI2USD = 788
  /// Convert an unsigned integer to the low SP FP elem and merge to a vector.
  | VCVTUSI2USS = 789
  /// Double Block Packed Sum-Absolute-Differences (SAD) on Unsigned Bytes.
  | VDBPSADBW = 790
  /// Divide Packed Double-Precision Floating-Point Values.
  | VDIVPD = 791
  /// Divide Packed Single-Precision Floating-Point Values.
  | VDIVPS = 792
  /// Divide Scalar Double-Precision Floating-Point Values.
  | VDIVSD = 793
  /// Divide Scalar Single-Precision Floating-Point Values.
  | VDIVSS = 794
  /// Dot Product of BF16 Pairs Accumulated into Packed Single Precision.
  | VDPBF16PS = 795
  /// Packed Double-Precision Dot Products.
  | VDPPD = 796
  /// Packed Single-Precision Dot Products.
  | VDPPS = 797
  /// Verify a Segment for Reading.
  | VERR = 798
  /// Verify a Segment for Writing.
  | VERW = 799
  /// Compute approximate base-2 exponential of packed DP FP elems of a vector.
  | VEXP2PD = 800
  /// Compute approximate base-2 exponential of packed SP FP elems of a vector.
  | VEXP2PS = 801
  /// Compute approximate base-2 exponential of the low DP FP elem of a vector.
  | VEXP2SD = 802
  /// Compute approximate base-2 exponential of the low SP FP elem of a vector.
  | VEXP2SS = 803
  /// Load Sparse Packed Double-Precision FP Values from Dense Memory.
  | VEXPANDPD = 804
  /// Load Sparse Packed Single-Precision FP Values from Dense Memory.
  | VEXPANDPS = 805
  /// Extract Packed Floating-Point Values.
  | VEXTRACTF128 = 806
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTF32X4 = 807
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTF32X8 = 808
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTF64X2 = 809
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTF64X4 = 810
  /// Extract packed Integer Values.
  | VEXTRACTI128 = 811
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTI32X4 = 812
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTI32X8 = 813
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTI64X2 = 814
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTI64X4 = 815
  /// Extract From Packed Single-Precision Floats.
  | VEXTRACTPS = 816
  /// Fix Up Special Packed Float64 Values.
  | VFIXUPIMMPD = 817
  /// Fix Up Special Packed Float32 Values.
  | VFIXUPIMMPS = 818
  /// Fix Up Special Scalar Float64 Value.
  | VFIXUPIMMSD = 819
  /// Fix Up Special Scalar Float32 Value.
  | VFIXUPIMMSS = 820
  /// Fused Multiply-Add of Packed Double-Precision Floating-Point Values.
  | VFMADD132PD = 821
  /// Fused Multiply-Add of Packed Single-Precision Floating-Point Values.
  | VFMADD132PS = 822
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD132SD = 823
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD132SS = 824
  /// Fused Multiply-Add of Packed Double-Precision Floating-Point Values.
  | VFMADD213PD = 825
  /// Fused Multiply-Add of Packed Single-Precision Floating-Point Values.
  | VFMADD213PS = 826
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD213SD = 827
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD213SS = 828
  /// Fused Multiply-Add of Packed Double-Precision Floating-Point Value.
  | VFMADD231PD = 829
  /// Fused Multiply-Add of Packed Single-Precision Floating-Point Values.
  | VFMADD231PS = 830
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD231SD = 831
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD231SS = 832
  /// Multiply and Add Packed Double-Precision Floating-Point(Only AMD).
  | VFMADDPD = 833
  /// Multiply and Add Packed Single-Precision Floating-Point(Only AMD).
  | VFMADDPS = 834
  /// Multiply and Add Scalar Double-Precision Floating-Point(Only AMD).
  | VFMADDSD = 835
  /// Multiply and Add Scalar Single-Precision Floating-Point(Only AMD).
  | VFMADDSS = 836
  /// Fused Multiply-Alternating Add/Sub of Packed Double-Precision FP Values.
  | VFMADDSUB132PD = 837
  /// Fused Multiply-Alternating Add/Sub of Packed Single-Precision FP Values.
  | VFMADDSUB132PS = 838
  /// Fused Multiply-Alternating Add/Sub of Packed Double-Precision FP Values.
  | VFMADDSUB213PD = 839
  /// Fused Multiply-Alternating Add/Sub of Packed Single-Precision FP Values.
  | VFMADDSUB213PS = 840
  /// Fused Multiply-Alternating Add/Sub of Packed Double-Precision FP Values.
  | VFMADDSUB231PD = 841
  /// Fused Multiply-Alternating Add/Sub of Packed Single-Precision FP Values.
  | VFMADDSUB231PS = 842
  /// Fused Multiply-Subtract of Packed Double-Precision Floating-Point Values.
  | VFMSUB132PD = 843
  /// Fused Multiply-Subtract of Packed Single-Precision Floating-Point Values.
  | VFMSUB132PS = 844
  /// Fused Multiply-Subtract of Scalar Double-Precision Floating-Point Values.
  | VFMSUB132SD = 845
  /// Fused Multiply-Subtract of Scalar Single-Precision Floating-Point Values.
  | VFMSUB132SS = 846
  /// Fused Multiply-Subtract of Packed Double-Precision Floating-Point Values.
  | VFMSUB213PD = 847
  /// Fused Multiply-Subtract of Packed Single-Precision Floating-Point Values.
  | VFMSUB213PS = 848
  /// Fused Multiply-Subtract of Scalar Double-Precision Floating-Point Values.
  | VFMSUB213SD = 849
  /// Fused Multiply-Subtract of Scalar Single-Precision Floating-Point Values.
  | VFMSUB213SS = 850
  /// Fused Multiply-Subtract of Packed Double-Precision Floating-Point Values.
  | VFMSUB231PD = 851
  /// Fused Multiply-Subtract of Packed Single-Precision Floating-Point Values.
  | VFMSUB231PS = 852
  /// Fused Multiply-Subtract of Scalar Double-Precision Floating-Point Values.
  | VFMSUB231SD = 853
  /// Fused Multiply-Subtract of Scalar Single-Precision Floating-Point Values.
  | VFMSUB231SS = 854
  /// Fused Multiply-Alternating Sub/Add of Packed Double-Precision FP Values.
  | VFMSUBADD132PD = 855
  /// Fused Multiply-Alternating Sub/Add of Packed Single-Precision FP Values.
  | VFMSUBADD132PS = 856
  /// Fused Multiply-Alternating Sub/Add of Packed Double-Precision FP Values.
  | VFMSUBADD213PD = 857
  /// Fused Multiply-Alternating Sub/Add of Packed Single-Precision FP Values.
  | VFMSUBADD213PS = 858
  /// Fused Multiply-Alternating Sub/Add of Packed Double-Precision FP Values.
  | VFMSUBADD231PD = 859
  /// Fused Multiply-Alternating Sub/Add of Packed Single-Precision FP Values.
  | VFMSUBADD231PS = 860
  /// Fused Negative Multiply-Add of Packed Double-Precision FP Values.
  | VFNMADD132PD = 861
  /// Fused Negative Mul-Add of Packed Single-Precision Floating-Point Values.
  | VFNMADD132PS = 862
  /// Fused Negative Multiply-Add of Scalar Double-Precision FP Values.
  | VFNMADD132SD = 863
  /// Fused Negative Mul-Add of Scalar Single-Precision Floating-Point Values.
  | VFNMADD132SS = 864
  /// Fused Negative Multiply-Add of Packed Double-Precision FP Values.
  | VFNMADD213PD = 865
  /// Fused Negative Mul-Add of Packed Single-Precision Floating-Point Values.
  | VFNMADD213PS = 866
  /// Fused Negative Multiply-Add of Scalar Double-Precision FP Values.
  | VFNMADD213SD = 867
  /// Fused Negative Mul-Add of Scalar Single-Precision Floating-Point Values.
  | VFNMADD213SS = 868
  /// Fused Negative Multiply-Add of Packed Double-Precision FP Values.
  | VFNMADD231PD = 869
  /// Fused Negative Mul-Add of Packed Single-Precision Floating-Point Values.
  | VFNMADD231PS = 870
  /// Fused Negative Multiply-Add of Scalar Double-Precision FP Values.
  | VFNMADD231SD = 871
  /// Fused Negative Mul-Add of Scalar Single-Precision Floating-Point Values.
  | VFNMADD231SS = 872
  /// Fused Negative Multiply-Subtract of Packed Double-Precision FP Values.
  | VFNMSUB132PD = 873
  /// Fused Negative Multiply-Subtract of Packed Single-Precision FP Values.
  | VFNMSUB132PS = 874
  /// Fused Negative Multiply-Subtract of Scalar Double-Precision FP Values.
  | VFNMSUB132SD = 875
  /// Fused Negative Multiply-Subtract of Scalar Single-Precision FP Values.
  | VFNMSUB132SS = 876
  /// Fused Negative Multiply-Subtract of Packed Double-Precision FP Values.
  | VFNMSUB213PD = 877
  /// Fused Negative Multiply-Subtract of Packed Single-Precision FP Values.
  | VFNMSUB213PS = 878
  /// Fused Negative Multiply-Subtract of Scalar Double-Precision FP Values.
  | VFNMSUB213SD = 879
  /// Fused Negative Multiply-Subtract of Scalar Single-Precision FP Values.
  | VFNMSUB213SS = 880
  /// Fused Negative Multiply-Subtract of Packed Double-Precision FP Values.
  | VFNMSUB231PD = 881
  /// Fused Negative Multiply-Subtract of Packed Single-Precision FP Values.
  | VFNMSUB231PS = 882
  /// Fused Negative Multiply-Subtract of Scalar Double-Precision FP Values.
  | VFNMSUB231SD = 883
  /// Fused Negative Multiply-Subtract of Scalar Single-Precision FP Values.
  | VFNMSUB231SS = 884
  /// Tests Types Of a Packed Float64 Values.
  | VFPCLASSPD = 885
  /// Tests Types Of a Packed Float32 Values.
  | VFPCLASSPS = 886
  /// Tests Types Of a Scalar Float64 Values.
  | VFPCLASSSD = 887
  /// Tests Types Of a Scalar Float32 Values.
  | VFPCLASSSS = 888
  /// Gather Packed DP FP Values Using Signed Dword/Qword Indices.
  | VGATHERDPD = 889
  /// Gather Packed SP FP values Using Signed Dword/Qword Indices.
  | VGATHERDPS = 890
  /// Sparse prefetch of packed DP FP vector with T0 hint using dword indices.
  | VGATHERPF0DPD = 891
  /// Sparse prefetch of packed SP FP vector with T0 hint using dword indices.
  | VGATHERPF0DPS = 892
  /// Sparse prefetch of packed DP FP vector with T0 hint using qword indices.
  | VGATHERPF0QPD = 893
  /// Sparse prefetch of packed SP FP vector with T0 hint using qword indices.
  | VGATHERPF0QPS = 894
  /// Sparse prefetch of packed DP FP vector with T1 hint using dword indices.
  | VGATHERPF1DPD = 895
  /// Sparse prefetch of packed SP FP vector with T1 hint using dword indices.
  | VGATHERPF1DPS = 896
  /// Sparse prefetch of packed DP FP vector with T1 hint using qword indices.
  | VGATHERPF1QPD = 897
  /// Sparse prefetch of packed SP FP vector with T1 hint using qword indices.
  | VGATHERPF1QPS = 898
  /// Gather Packed DP FP Values Using Signed Dword/Qword Indices.
  | VGATHERQPD = 899
  /// Gather Packed SP FP values Using Signed Dword/Qword Indices.
  | VGATHERQPS = 900
  /// Convert Exponents of Packed DP FP Values to DP FP Values.
  | VGETEXPPD = 901
  /// Convert Exponents of Packed SP FP Values to SP FP Values.
  | VGETEXPPS = 902
  /// Convert Exponents of Scalar DP FP Values to DP FP Value.
  | VGETEXPSD = 903
  /// Convert Exponents of Scalar SP FP Values to SP FP Value.
  | VGETEXPSS = 904
  /// Extract Float64 Vector of Normalized Mantissas from Float64 Vector.
  | VGETMANTPD = 905
  /// Extract Float32 Vector of Normalized Mantissas from Float32 Vector.
  | VGETMANTPS = 906
  /// Extract Float64 of Normalized Mantissas from Float64 Scalar.
  | VGETMANTSD = 907
  /// Extract Float32 Vector of Normalized Mantissa from Float32 Vector.
  | VGETMANTSS = 908
  /// Galois Field Affine Transformation Inverse.
  | VGF2P8AFFINEINVQB = 909
  /// Galois Field Affine Transformation.
  | VGF2P8AFFINEQB = 910
  /// Galois Field Multiply Bytes.
  | VGF2P8MULB = 911
  /// Packed Double-FP Horizontal Add.
  | VHADDPD = 912
  /// Packed Single-FP Horizontal Add.
  | VHADDPS = 913
  /// Packed Double-FP Horizontal Subtract.
  | VHSUBPD = 914
  /// Packed Single-FP Horizontal Subtract.
  | VHSUBPS = 915
  /// Insert Packed Floating-Point Values.
  | VINSERTF128 = 916
  /// Insert Packed Floating-Point Values.
  | VINSERTF32X4 = 917
  /// Insert Packed Floating-Point Values.
  | VINSERTF64X2 = 918
  /// Insert Packed Floating-Point Values.
  | VINSERTF64X4 = 919
  /// Insert Packed Integer Values.
  | VINSERTI128 = 920
  /// Insert 256 bits of packed doubleword integer values.
  | VINSERTI32X8 = 921
  /// Insert Packed Floating-Point Values.
  | VINSERTI64X2 = 922
  /// Insert 256 bits of packed quadword integer values.
  | VINSERTI64X4 = 923
  /// Insert Into Packed Single-Precision Floats.
  | VINSERTPS = 924
  /// Load Unaligned Integer 128 Bits.
  | VLDDQU = 925
  /// Store Selected Bytes of Double Quadword.
  | VMASKMOVDQU = 926
  /// Conditional SIMD Packed Loads and Stores.
  | VMASKMOVPD = 927
  /// Conditional SIMD Packed Loads and Stores.
  | VMASKMOVPS = 928
  /// Return Maximum Packed Double-Precision Floating-Point Values.
  | VMAXPD = 929
  /// Maximum of Packed Single-Precision Floating-Point Values.
  | VMAXPS = 930
  /// Return Maximum Scalar Double-Precision Floating-Point Value.
  | VMAXSD = 931
  /// Return Maximum Scalar Single-Precision Floating-Point Value.
  | VMAXSS = 932
  /// Call to VM Monitor.
  | VMCALL = 933
  /// Clear Virtual-Machine Control Structure.
  | VMCLEAR = 934
  /// Invoke VM function.
  | VMFUNC = 935
  /// Return Minimum Packed Double-Precision Floating-Point Values.
  | VMINPD = 936
  /// Return Minimum Packed Single-Precision Floating-Point Values.
  | VMINPS = 937
  /// Return Minimum Scalar Double-Precision Floating-Point Value.
  | VMINSD = 938
  /// Return Minimum Scalar Single-Precision Floating-Point Value.
  | VMINSS = 939
  /// Launch Virtual Machine.
  | VMLAUNCH = 940
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | VMOVAPD = 941
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | VMOVAPS = 942
  /// Move Doubleword.
  | VMOVD = 943
  /// Move One Double-FP and Duplicate.
  | VMOVDDUP = 944
  /// Move Aligned Double Quadword.
  | VMOVDQA = 945
  /// Move Aligned Double Quadword.
  | VMOVDQA32 = 946
  /// Move Aligned Double Quadword.
  | VMOVDQA64 = 947
  /// Move Unaligned Double Quadword.
  | VMOVDQU = 948
  /// VMOVDQU with 16-bit granular conditional update.
  | VMOVDQU16 = 949
  /// Move Unaligned Double Quadword.
  | VMOVDQU32 = 950
  /// Move Unaligned Double Quadword.
  | VMOVDQU64 = 951
  /// VMOVDQU with 8-bit granular conditional update.
  | VMOVDQU8 = 952
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | VMOVHLPS = 953
  /// Move High Packed Double-Precision Floating-Point Value.
  | VMOVHPD = 954
  /// Move High Packed Single-Precision Floating-Point Values.
  | VMOVHPS = 955
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | VMOVLHPS = 956
  /// Move Low Packed Double-Precision Floating-Point Value.
  | VMOVLPD = 957
  /// Move Low Packed Single-Precision Floating-Point Values.
  | VMOVLPS = 958
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | VMOVMSKPD = 959
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | VMOVMSKPS = 960
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | VMOVNTDQ = 961
  /// Load Double Quadword Non-temporal Aligned.
  | VMOVNTDQA = 962
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPD = 963
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPS = 964
  /// Move Quadword.
  | VMOVQ = 965
  /// Move Data from String to String (doubleword).
  | VMOVSD = 966
  /// Move Packed Single-FP High and Duplicate.
  | VMOVSHDUP = 967
  /// Move Packed Single-FP Low and Duplicate.
  | VMOVSLDUP = 968
  /// Move Scalar Single-Precision Floating-Point Values.
  | VMOVSS = 969
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | VMOVUPD = 970
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | VMOVUPS = 971
  /// Compute Multiple Packed Sums of Absolute Difference.
  | VMPSADBW = 972
  /// Load Pointer to Virtual-Machine Control Structure.
  | VMPTRLD = 973
  /// Store Pointer to Virtual-Machine Control Structure.
  | VMPTRST = 974
  /// Reads a component from the VMCS and stores it into a destination operand.
  | VMREAD = 975
  /// Resume Virtual Machine.
  | VMRESUME = 976
  /// Multiply Packed Double-Precision Floating-Point Values.
  | VMULPD = 977
  /// Multiply Packed Single-Precision Floating-Point Values.
  | VMULPS = 978
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | VMULSD = 979
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | VMULSS = 980
  /// Writes a component to the VMCS from a source operand.
  | VMWRITE = 981
  /// Leave VMX Operation.
  | VMXOFF = 982
  /// Enter VMX Operation.
  | VMXON = 983
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | VORPD = 984
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | VORPS = 985
  /// Compute Intersection Between dwords.
  | VP2INTERSECTD = 986
  /// Compute Intersection Between qwords.
  | VP2INTERSECTQ = 987
  /// Dot Product of Signed Words with Dword Accumulation.
  | VP4DPWSSD = 988
  /// Dot Product of Signed Words with Dword Accumulation and Saturation.
  | VP4DPWSSDS = 989
  /// Packed Absolute Value (byte).
  | VPABSB = 990
  /// Packed Absolute Value (dword).
  | VPABSD = 991
  /// Packed Absolute Value (qword).
  | VPABSQ = 992
  /// Packed Absolute Value (word).
  | VPABSW = 993
  /// Pack with Signed Saturation.
  | VPACKSSDW = 994
  /// Pack with Signed Saturation.
  | VPACKSSWB = 995
  /// Pack with Unsigned Saturation.
  | VPACKUSDW = 996
  /// Pack with Unsigned Saturation.
  | VPACKUSWB = 997
  /// Add Packed byte Integers.
  | VPADDB = 998
  /// Add Packed Doubleword Integers.
  | VPADDD = 999
  /// Add Packed Quadword Integers.
  | VPADDQ = 1000
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | VPADDSB = 1001
  /// Add Packed Signed Integers with Signed Saturation (word).
  | VPADDSW = 1002
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPADDUSB = 1003
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | VPADDUSW = 1004
  /// Add Packed word Integers.
  | VPADDW = 1005
  /// Packed Align Right.
  | VPALIGNR = 1006
  /// Logical AND.
  | VPAND = 1007
  /// Logical AND.
  | VPANDD = 1008
  /// Logical AND NOT.
  | VPANDN = 1009
  /// Logical AND.
  | VPANDQ = 1010
  /// Average Packed Integers (byte).
  | VPAVGB = 1011
  /// Average Packed Integers (word).
  | VPAVGW = 1012
  /// Blend Packed Dwords.
  | VPBLENDD = 1013
  /// Blend Byte/Word Vectors Using an Opmask Control.
  | VPBLENDMB = 1014
  /// Blend Int32/Int64 Vectors Using an OpMask Control.
  | VPBLENDMD = 1015
  /// Blend qword elements using opmask as select control.
  | VPBLENDMQ = 1016
  /// Blend word elements using opmask as select control.
  | VPBLENDMW = 1017
  /// Variable Blend Packed Bytes.
  | VPBLENDVB = 1018
  /// Blend Packed Words.
  | VPBLENDW = 1019
  /// Broadcast Integer Data.
  | VPBROADCASTB = 1020
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTD = 1021
  /// Broadcast Mask to Vector Register.
  | VPBROADCASTM = 1022
  /// Broadcast low byte value in k1.
  | VPBROADCASTMB2Q = 1023
  /// Broadcast low word value in k1.
  | VPBROADCASTMW2D = 1024
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTQ = 1025
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTW = 1026
  /// Carry-Less Multiplication Quadword.
  | VPCLMULQDQ = 1027
  /// Compare packed signed bytes using specified primitive.
  | VPCMPB = 1028
  /// Compare packed signed dwords using specified primitive.
  | VPCMPD = 1029
  /// Compare Packed Data for Equal (byte).
  | VPCMPEQB = 1030
  /// Compare Packed Data for Equal (doubleword).
  | VPCMPEQD = 1031
  /// Compare Packed Data for Equal (quadword).
  | VPCMPEQQ = 1032
  /// Compare Packed Data for Equal (word).
  | VPCMPEQW = 1033
  /// Packed Compare Explicit Length Strings, Return Index.
  | VPCMPESTRI = 1034
  /// Packed Compare Explicit Length Strings, Return Mask.
  | VPCMPESTRM = 1035
  /// Compare Packed Signed Integers for Greater Than (byte).
  | VPCMPGTB = 1036
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | VPCMPGTD = 1037
  /// Compare Packed Data for Greater Than (qword).
  | VPCMPGTQ = 1038
  /// Compare Packed Signed Integers for Greater Than (word).
  | VPCMPGTW = 1039
  /// Packed Compare Implicit Length Strings, Return Index.
  | VPCMPISTRI = 1040
  /// Packed Compare Implicit Length Strings, Return Mask.
  | VPCMPISTRM = 1041
  /// Compare packed signed quadwords using specified primitive.
  | VPCMPQ = 1042
  /// Compare packed unsigned bytes using specified primitive.
  | VPCMPUB = 1043
  /// Compare packed unsigned dwords using specified primitive.
  | VPCMPUD = 1044
  /// Compare packed unsigned quadwords using specified primitive.
  | VPCMPUQ = 1045
  /// Compare packed unsigned words using specified primitive.
  | VPCMPUW = 1046
  /// Compare packed signed words using specified primitive.
  | VPCMPW = 1047
  /// Compare packed unsigned bytes using specified primitive.
  | VPCMUB = 1048
  /// Compare packed unsigned dwords using specified primitive.
  | VPCMUD = 1049
  /// Compare packed unsigned quadwords using specified primitive.
  | VPCMUQ = 1050
  /// Compare packed unsigned words using specified primitive.
  | VPCMUW = 1051
  /// Store Sparse Packed Byte Integer Values into Dense Memory/Register.
  | VPCOMPRESSB = 1052
  /// Store Sparse Packed Doubleword Integer Values into Dense Memory/Register.
  | VPCOMPRESSD = 1053
  /// Store Sparse Packed Quadword Integer Values into Dense Memory/Register.
  | VPCOMPRESSQ = 1054
  /// Store Sparse Packed Word Integer Values into Dense Memory/Register.
  | VPCOMPRESSW = 1055
  /// Detect conflicts within a vector of packed 32/64-bit integers.
  | VPCONFLICTD = 1056
  /// Detect conflicts within a vector of packed 64-bit integers.
  | VPCONFLICTQ = 1057
  /// Multiply and Add Unsigned and Signed Bytes.
  | VPDPBUSD = 1058
  /// Multiply and Add Unsigned and Signed Bytes with Saturation.
  | VPDPBUSDS = 1059
  /// Multiply and Add Signed Word Integers.
  | VPDPWSSD = 1060
  /// Multiply and Add Signed Word Integers with Saturation.
  | VPDPWSSDS = 1061
  /// Permute Floating-Point Values.
  | VPERM2F128 = 1062
  /// Permute Integer Values.
  | VPERM2I128 = 1063
  /// Permute packed bytes elements.
  | VPERMB = 1064
  /// Permute Packed Doublewords/Words Elements.
  | VPERMD = 1065
  /// Full Permute of Bytes from Two Tables Overwriting the Index.
  | VPERMI2B = 1066
  /// Full permute of two tables of dword elements overwriting the index vector.
  | VPERMI2D = 1067
  /// Full permute of two tables of DP elements overwriting the index vector.
  | VPERMI2PD = 1068
  /// Full permute of two tables of SP elements overwriting the index vector.
  | VPERMI2PS = 1069
  /// Full permute of two tables of qword elements overwriting the index vector.
  | VPERMI2Q = 1070
  /// Full Permute From Two Tables Overwriting the Index.
  | VPERMI2W = 1071
  /// Permute Double-Precision Floating-Point Values.
  | VPERMILPD = 1072
  /// Permute Single-Precision Floating-Point Values.
  | VPERMILPS = 1073
  /// Permute Double-Precision Floating-Point Elements.
  | VPERMPD = 1074
  /// Permute Single-Precision Floating-Point Elements.
  | VPERMPS = 1075
  /// Qwords Element Permutation.
  | VPERMQ = 1076
  /// Full permute of two tables of byte elements overwriting one source table.
  | VPERMT2B = 1077
  /// Full permute of two tables of dword elements overwriting one source table.
  | VPERMT2D = 1078
  /// Full permute of two tables of DP elements overwriting one source table.
  | VPERMT2PD = 1079
  /// Full permute of two tables of SP elements overwriting one source table.
  | VPERMT2PS = 1080
  /// Full permute of two tables of qword elements overwriting one source table.
  | VPERMT2Q = 1081
  /// Full permute of two tables of word elements overwriting one source table.
  | VPERMT2W = 1082
  /// Permute packed word elements.
  | VPERMW = 1083
  /// Load Sparse Packed Byte Integer Values from Dense Memory / Register.
  | VPEXPANDB = 1084
  /// Load Sparse Packed Doubleword Integer Values from Dense Memory / Register.
  | VPEXPANDD = 1085
  /// Load Sparse Packed Quadword Integer Values from Dense Memory / Register.
  | VPEXPANDQ = 1086
  /// Load Sparse Packed Word Integer Values from Dense Memory / Register.
  | VPEXPANDW = 1087
  /// Extract Byte.
  | VPEXTRB = 1088
  /// Extract Dword.
  | VPEXTRD = 1089
  /// Extract Qword.
  | VPEXTRQ = 1090
  /// Extract Word.
  | VPEXTRW = 1091
  /// Gather packed dword values using signed Dword/Qword indices.
  | VPGATHERDD = 1092
  /// Gather Packed Qword Values Using Signed Dword/Qword Indices.
  | VPGATHERDQ = 1093
  /// Gather Packed Dword Values Using Signed Dword/Qword Indices.
  | VPGATHERQD = 1094
  /// Gather Packed Qword Values Using Signed Dword/Qword Indices.
  | VPGATHERQQ = 1095
  /// Packed Horizontal Add (32-bit).
  | VPHADDD = 1096
  /// Packed Horizontal Add and Saturate (16-bit).
  | VPHADDSW = 1097
  /// Packed Horizontal Add (16-bit).
  | VPHADDW = 1098
  /// Packed Horizontal Word Minimum.
  | VPHMINPOSUW = 1099
  /// Packed Horizontal Subtract (32-bit).
  | VPHSUBD = 1100
  /// Packed Horizontal Subtract and Saturate (16-bit).
  | VPHSUBSW = 1101
  /// Packed Horizontal Subtract (16-bit).
  | VPHSUBW = 1102
  /// Insert Byte.
  | VPINSRB = 1103
  /// Insert Dword.
  | VPINSRD = 1104
  /// Insert Qword.
  | VPINSRQ = 1105
  /// Insert Word.
  | VPINSRW = 1106
  /// Count the number of leading zero bits of packed dword elements.
  | VPLZCNTD = 1107
  /// Count the number of leading zero bits of packed qword elements.
  | VPLZCNTQ = 1108
  /// Packed Multiply of Unsigned 52-bit and Add High 52-bit Products.
  | VPMADD52HUQ = 1109
  /// Packed Multiply of Unsigned 52-bit and Add Low 52-bit Products.
  | VPMADD52LUQ = 1110
  /// Multiply and Add Packed Signed and Unsigned Bytes.
  | VPMADDUBSW = 1111
  /// Multiply and Add Packed Integers.
  | VPMADDWD = 1112
  /// Conditional SIMD Integer Packed Loads and Stores.
  | VPMASKMOVD = 1113
  /// Conditional SIMD Integer Packed Loads and Stores.
  | VPMASKMOVQ = 1114
  /// Maximum of Packed Signed Integers (byte).
  | VPMAXSB = 1115
  /// Maximum of Packed Signed Integers (dword).
  | VPMAXSD = 1116
  /// Compute maximum of packed signed 64-bit integer elements.
  | VPMAXSQ = 1117
  /// Maximum of Packed Signed Word Integers.
  | VPMAXSW = 1118
  /// Maximum of Packed Unsigned Byte Integers.
  | VPMAXUB = 1119
  /// Maximum of Packed Unsigned Integers (dword).
  | VPMAXUD = 1120
  /// Compute maximum of packed unsigned 64-bit integer elements.
  | VPMAXUQ = 1121
  /// Maximum of Packed Unsigned Integers (word).
  | VPMAXUW = 1122
  /// Minimum of Packed Signed Integers (byte).
  | VPMINSB = 1123
  /// Minimum of Packed Signed Integers (dword).
  | VPMINSD = 1124
  /// Compute minimum of packed signed 64-bit integer elements.
  | VPMINSQ = 1125
  /// Minimum of Packed Signed Word Integers.
  | VPMINSW = 1126
  /// Minimum of Packed Unsigned Byte Integers.
  | VPMINUB = 1127
  /// Minimum of Packed Dword Integers.
  | VPMINUD = 1128
  /// Compute minimum of packed unsigned 64-bit integer elements.
  | VPMINUQ = 1129
  /// Minimum of Packed Unsigned Integers (word).
  | VPMINUW = 1130
  /// Convert a vector register in 32/64-bit granularity to an opmask register.
  | VPMOVB2D = 1131
  /// Convert a Vector Register to a Mask.
  | VPMOVB2M = 1132
  /// Convert dword vector register to mask register.
  | VPMOVD2M = 1133
  /// Down Convert DWord to Byte.
  | VPMOVDB = 1134
  /// Down Convert DWord to Word.
  | VPMOVDW = 1135
  /// Convert opmask register to vector register in 8-bit granularity.
  | VPMOVM2B = 1136
  /// Convert opmask register to vector register in 32-bit granularity.
  | VPMOVM2D = 1137
  /// Convert opmask register to vector register in 64-bit granularity.
  | VPMOVM2Q = 1138
  /// Convert opmask register to vector register in 16-bit granularity.
  | VPMOVM2W = 1139
  /// Move Byte Mask.
  | VPMOVMSKB = 1140
  /// Convert qword vector register to mask register.
  | VPMOVQ2M = 1141
  /// Down Convert QWord to Byte.
  | VPMOVQB = 1142
  /// Down Convert QWord to DWord.
  | VPMOVQD = 1143
  /// Down Convert QWord to Word.
  | VPMOVQW = 1144
  /// Down Convert DWord to Byte.
  | VPMOVSDB = 1145
  /// Down Convert DWord to Word.
  | VPMOVSDW = 1146
  /// Down Convert QWord to Byte.
  | VPMOVSQB = 1147
  /// Down Convert QWord to Dword.
  | VPMOVSQD = 1148
  /// Down Convert QWord to Word.
  | VPMOVSQW = 1149
  /// Down Convert Word to Byte.
  | VPMOVSWB = 1150
  /// Packed Move with Sign Extend (8-bit to 32-bit).
  | VPMOVSXBD = 1151
  /// Packed Move with Sign Extend (8-bit to 64-bit).
  | VPMOVSXBQ = 1152
  /// Packed Move with Sign Extend (8-bit to 16-bit).
  | VPMOVSXBW = 1153
  /// Packed Move with Sign Extend (32-bit to 64-bit).
  | VPMOVSXDQ = 1154
  /// Packed Move with Sign Extend (16-bit to 32-bit).
  | VPMOVSXWD = 1155
  /// Packed Move with Sign Extend (16-bit to 64-bit).
  | VPMOVSXWQ = 1156
  /// Down Convert DWord to Byte.
  | VPMOVUSDB = 1157
  /// Down Convert DWord to Word.
  | VPMOVUSDW = 1158
  /// Down Convert QWord to Byte.
  | VPMOVUSQB = 1159
  /// Down Convert QWord to DWord.
  | VPMOVUSQD = 1160
  /// Down Convert QWord to Word.
  | VPMOVUSQW = 1161
  /// Down Convert Word to Byte.
  | VPMOVUSWB = 1162
  /// Convert a vector register in 16-bit granularity to an opmask register.
  | VPMOVW2M = 1163
  /// Down convert word elements in a vector to byte elements using truncation.
  | VPMOVWB = 1164
  /// Packed Move with Zero Extend (8-bit to 32-bit).
  | VPMOVZXBD = 1165
  /// Packed Move with Zero Extend (8-bit to 64-bit).
  | VPMOVZXBQ = 1166
  /// Packed Move with Zero Extend (8-bit to 16-bit).
  | VPMOVZXBW = 1167
  /// Packed Move with Zero Extend (32-bit to 64-bit).
  | VPMOVZXDQ = 1168
  /// Packed Move with Zero Extend (16-bit to 32-bit).
  | VPMOVZXWD = 1169
  /// Packed Move with Zero Extend (16-bit to 64-bit).
  | VPMOVZXWQ = 1170
  /// Multiply Packed Doubleword Integers.
  | VPMULDQ = 1171
  /// Packed Multiply High with Round and Scale.
  | VPMULHRSW = 1172
  /// Multiply Packed Unsigned Integers and Store High Result.
  | VPMULHUW = 1173
  /// Multiply Packed Signed Integers and Store High Result.
  | VPMULHW = 1174
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLD = 1175
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLQ = 1176
  /// Multiply Packed Signed Integers and Store Low Result.
  | VPMULLW = 1177
  /// Select Packed Unaligned Bytes from Quadword Sources.
  | VPMULTISHIFTQB = 1178
  /// Multiply Packed Unsigned Doubleword Integers.
  | VPMULUDQ = 1179
  /// Return the Count of Number of Bits Set to 1 in byte.
  | VPOPCNTB = 1180
  /// Return the Count of Number of Bits Set to 1 in dword.
  | VPOPCNTD = 1181
  /// Return the Count of Number of Bits Set to 1 in qword.
  | VPOPCNTQ = 1182
  /// Return the Count of Number of Bits Set to 1 in word.
  | VPOPCNTW = 1183
  /// Bitwise Logical OR.
  | VPOR = 1184
  /// Bitwise Logical OR.
  | VPORD = 1185
  /// Bitwise Logical OR.
  | VPORQ = 1186
  /// Rotate dword elem left by a constant shift count with conditional update.
  | VPROLD = 1187
  /// Rotate qword elem left by a constant shift count with conditional update.
  | VPROLQ = 1188
  /// Rotate dword element left by shift counts specified.
  | VPROLVD = 1189
  /// Rotate qword element left by shift counts specified.
  | VPROLVQ = 1190
  /// Rotate dword element right by a constant shift count.
  | VPRORD = 1191
  /// Rotate qword element right by a constant shift count.
  | VPRORQ = 1192
  /// Rotate dword element right by shift counts specified.
  | VPRORRD = 1193
  /// Rotate qword element right by shift counts specified.
  | VPRORRQ = 1194
  /// Rotate dword element right by shift counts specified.
  | VPRORVD = 1195
  /// Rotate qword element right by shift counts specified.
  | VPRORVQ = 1196
  /// Compute Sum of Absolute Differences.
  | VPSADBW = 1197
  /// Scatter dword elements in a vector to memory using dword indices.
  | VPSCATTERDD = 1198
  /// Scatter qword elements in a vector to memory using dword indices.
  | VPSCATTERDQ = 1199
  /// Scatter dword elements in a vector to memory using qword indices.
  | VPSCATTERQD = 1200
  /// Scatter qword elements in a vector to memory using qword indices.
  | VPSCATTERQQ = 1201
  /// Concatenate and Shift Packed Data Left Logical.
  | VPSHLDD = 1202
  /// Concatenate and Shift Packed Data Left Logical.
  | VPSHLDQ = 1203
  /// Concatenate and Variable Shift Packed Data Left Logical.
  | VPSHLDVD = 1204
  /// Concatenate and Variable Shift Packed Data Left Logical.
  | VPSHLDVQ = 1205
  /// Concatenate and Variable Shift Packed Data Left Logical.
  | VPSHLDVW = 1206
  /// Concatenate and Shift Packed Data Left Logical.
  | VPSHLDW = 1207
  /// Concatenate and Shift Packed Data Right Logical.
  | VPSHRDD = 1208
  /// Concatenate and Shift Packed Data Right Logical.
  | VPSHRDQ = 1209
  /// Concatenate and Variable Shift Packed Data Right Logical.
  | VPSHRDVD = 1210
  /// Concatenate and Variable Shift Packed Data Right Logical.
  | VPSHRDVQ = 1211
  /// Concatenate and Variable Shift Packed Data Right Logical.
  | VPSHRDVW = 1212
  /// Concatenate and Shift Packed Data Right Logical.
  | VPSHRDW = 1213
  /// Packed Shuffle Bytes.
  | VPSHUFB = 1214
  /// Shuffle Bits from Quadword Elements Using Byte Indexes into Mask.
  | VPSHUFBITQMB = 1215
  /// Shuffle Packed Doublewords.
  | VPSHUFD = 1216
  /// Shuffle Packed High Words.
  | VPSHUFHW = 1217
  /// Shuffle Packed Low Words.
  | VPSHUFLW = 1218
  /// Packed SIGN (byte).
  | VPSIGNB = 1219
  /// Packed SIGN (doubleword).
  | VPSIGND = 1220
  /// Packed SIGN (word).
  | VPSIGNW = 1221
  /// Shift Packed Data Left Logical (doubleword).
  | VPSLLD = 1222
  /// Shift Double Quadword Left Logical.
  | VPSLLDQ = 1223
  /// Shift Packed Data Left Logical (quadword).
  | VPSLLQ = 1224
  /// Variable Bit Shift Left Logical.
  | VPSLLVD = 1225
  /// Variable Bit Shift Left Logical.
  | VPSLLVQ = 1226
  /// Variable Bit Shift Left Logical.
  | VPSLLVW = 1227
  /// Shift Packed Data Left Logical (word).
  | VPSLLW = 1228
  /// Shift Packed Data Right Arithmetic (doubleword).
  | VPSRAD = 1229
  /// Shift qwords right by a constant shift count and shifting in sign bits.
  | VPSRAQ = 1230
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVD = 1231
  /// Shift qwords right by shift counts in a vector and shifting in sign bits.
  | VPSRAVQ = 1232
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVW = 1233
  /// Shift Packed Data Right Arithmetic (word).
  | VPSRAW = 1234
  /// Shift Packed Data Right Logical (doubleword).
  | VPSRLD = 1235
  /// Shift Double Quadword Right Logical.
  | VPSRLDQ = 1236
  /// Shift Packed Data Right Logical (quadword).
  | VPSRLQ = 1237
  /// Variable Bit Shift Right Logical.
  | VPSRLVD = 1238
  /// Variable Bit Shift Right Logical.
  | VPSRLVQ = 1239
  /// Variable Bit Shift Right Logical.
  | VPSRLVW = 1240
  /// Shift Packed Data Right Logical (word).
  | VPSRLW = 1241
  /// Subtract Packed Integers (byte).
  | VPSUBB = 1242
  /// Subtract Packed Integers (doubleword).
  | VPSUBD = 1243
  /// Subtract Packed Integers (quadword).
  | VPSUBQ = 1244
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | VPSUBSB = 1245
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | VPSUBSW = 1246
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPSUBUSB = 1247
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | VPSUBUSW = 1248
  /// Subtract Packed Integers (word).
  | VPSUBW = 1249
  /// Perform bitwise ternary logic operation of three vectors.
  | VPTERLOGD = 1250
  /// Perform bitwise ternary logic operation of three vectors.
  | VPTERLOGQ = 1251
  /// Bitwise Ternary Logic.
  | VPTERNLOGD = 1252
  /// Bitwise Ternary Logic.
  | VPTERNLOGQ = 1253
  /// Logical Compare.
  | VPTEST = 1254
  /// Perform bitwise AND of byte elems of two vecs and write results to opmask.
  | VPTESTMB = 1255
  /// Perform bitwise AND of dword elems of 2-vecs and write results to opmask.
  | VPTESTMD = 1256
  /// Perform bitwise AND of qword elems of 2-vecs and write results to opmask.
  | VPTESTMQ = 1257
  /// Perform bitwise AND of word elems of two vecs and write results to opmask.
  | VPTESTMW = 1258
  /// Perform bitwise NAND of byte elems of 2-vecs and write results to opmask.
  | VPTESTNMB = 1259
  /// Perform bitwise NAND of dword elems of 2-vecs and write results to opmask.
  | VPTESTNMD = 1260
  /// Perform bitwise NAND of qword elems of 2-vecs and write results to opmask.
  | VPTESTNMQ = 1261
  /// Perform bitwise NAND of word elems of 2-vecs and write results to opmask.
  | VPTESTNMW = 1262
  /// Unpack High Data.
  | VPUNPCKHBW = 1263
  /// Unpack High Data.
  | VPUNPCKHDQ = 1264
  /// Unpack High Data.
  | VPUNPCKHQDQ = 1265
  /// Unpack High Data.
  | VPUNPCKHWD = 1266
  /// Unpack Low Data.
  | VPUNPCKLBW = 1267
  /// Unpack Low Data.
  | VPUNPCKLDQ = 1268
  /// Unpack Low Data.
  | VPUNPCKLQDQ = 1269
  /// Unpack Low Data.
  | VPUNPCKLWD = 1270
  /// Logical Exclusive OR.
  | VPXOR = 1271
  /// Bitwise XOR of packed doubleword integers.
  | VPXORD = 1272
  /// Bitwise XOR of packed quadword integers.
  | VPXORQ = 1273
  /// Range Restriction Calculation For Packed Pairs of Float64 Values.
  | VRANGEPD = 1274
  /// Range Restriction Calculation For Packed Pairs of Float32 Values.
  | VRANGEPS = 1275
  /// Range Restriction Calculation From a pair of Scalar Float64 Values.
  | VRANGESD = 1276
  /// Range Restriction Calculation From a Pair of Scalar Float32 Values.
  | VRANGESS = 1277
  /// Compute Approximate Reciprocals of Packed Float64 Values.
  | VRCP14PD = 1278
  /// Compute Approximate Reciprocals of Packed Float32 Values.
  | VRCP14PS = 1279
  /// Compute Approximate Reciprocal of Scalar Float64 Value.
  | VRCP14SD = 1280
  /// Compute Approximate Reciprocal of Scalar Float32 Value.
  | VRCP14SS = 1281
  /// Computes the reciprocal approximation of the float64 values.
  | VRCP28PD = 1282
  /// Computes the reciprocal approximation of the float32 values.
  | VRCP28PS = 1283
  /// Computes the reciprocal approximation of the low float64 value.
  | VRCP28SD = 1284
  /// Computes the reciprocal approximation of the low float32 value.
  | VRCP28SS = 1285
  /// Compute reciprocals of packed single-precision floating-point values.
  | VRCPPS = 1286
  /// Compute Reciprocal of Scalar Single-Precision Floating-Point Values.
  | VRCPSS = 1287
  /// Perform Reduction Transformation on Packed Float64 Values.
  | VREDUCEPD = 1288
  /// Perform Reduction Transformation on Packed Float32 Values.
  | VREDUCEPS = 1289
  /// Perform a Reduction Transformation on a Scalar Float64 Value.
  | VREDUCESD = 1290
  /// Perform a Reduction Transformation on a Scalar Float32 Value.
  | VREDUCESS = 1291
  /// Round Packed Float64 Values To Include A Given Number Of Fraction Bits.
  | VRNDSCALEPD = 1292
  /// Round Packed Float32 Values To Include A Given Number Of Fraction Bits.
  | VRNDSCALEPS = 1293
  /// Round Scalar Float64 Value To Include A Given Number Of Fraction Bits.
  | VRNDSCALESD = 1294
  /// Round Scalar Float32 Value To Include A Given Number Of Fraction Bits.
  | VRNDSCALESS = 1295
  /// Round Packed Double-Precision Values.
  | VROUNDPD = 1296
  /// Round Packed Single-Precision Values.
  | VROUNDPS = 1297
  /// Round Scalar Double-Precision Value.
  | VROUNDSD = 1298
  /// Round Scalar Single-Precision Value.
  | VROUNDSS = 1299
  /// Compute Approximate Reciprocals of Square Roots of Packed Float64 Values.
  | VRSQRT14PD = 1300
  /// Compute Approximate Reciprocals of Square Roots of Packed Float32 Values.
  | VRSQRT14PS = 1301
  /// Compute Approximate Reciprocal of Square Root of Scalar Float64 Value.
  | VRSQRT14SD = 1302
  /// Compute Approximate Reciprocal of Square Root of Scalar Float32 Value.
  | VRSQRT14SS = 1303
  /// Computes the reciprocal square root of the float64 values.
  | VRSQRT28PD = 1304
  /// Computes the reciprocal square root of the float32 values.
  | VRSQRT28PS = 1305
  /// Computes the reciprocal square root of the low float64 value.
  | VRSQRT28SD = 1306
  /// Computes the reciprocal square root of the low float32 value.
  | VRSQRT28SS = 1307
  /// Compute Reciprocals of Square Roots of Packed Single-Precision FP Values.
  | VRSQRTPS = 1308
  /// Compute Reciprocal of Square Root of Scalar Single-Precision FP Value.
  | VRSQRTSS = 1309
  /// Scale Packed Float64 Values With Float64 Values.
  | VSCALEFPD = 1310
  /// Scale Packed Float32 Values With Float32 Values.
  | VSCALEFPS = 1311
  /// Scale Scalar Float64 Values With Float64 Values.
  | VSCALEFSD = 1312
  /// Scale Scalar Float32 Value With Float32 Value.
  | VSCALEFSS = 1313
  /// Multiply packed DP FP elements of a vector by powers.
  | VSCALEPD = 1314
  /// Multiply packed SP FP elements of a vector by powers.
  | VSCALEPS = 1315
  /// Multiply the low DP FP element of a vector by powers.
  | VSCALESD = 1316
  /// Multiply the low SP FP element of a vector by powers.
  | VSCALESS = 1317
  /// Scatter SP/DP FP elements in a vector to memory using dword indices.
  | VSCATTERDD = 1318
  /// Scatter packed double with signed dword indices.
  | VSCATTERDPD = 1319
  /// Scatter packed single with signed dword indices.
  | VSCATTERDPS = 1320
  /// Scatter SP/DP FP elements in a vector to memory using dword indices.
  | VSCATTERDQ = 1321
  /// Sparse prefetch packed DP FP with T0 hint to write using dword indices.
  | VSCATTERPF0DPD = 1322
  /// Sparse prefetch packed SP FP with T0 hint to write using dword indices.
  | VSCATTERPF0DPS = 1323
  /// Sparse prefetch packed DP FP with T0 hint to write using qword indices.
  | VSCATTERPF0QPD = 1324
  /// Sparse prefetch packed SP FP with T0 hint to write using qword indices.
  | VSCATTERPF0QPS = 1325
  /// Sparse prefetch packed DP FP with T1 hint to write using dword indices.
  | VSCATTERPF1DPD = 1326
  /// Sparse prefetch packed SP FP with T1 hint to write using dword indices.
  | VSCATTERPF1DPS = 1327
  /// Sparse prefetch packed DP FP with T1 hint to write using qword indices.
  | VSCATTERPF1QPD = 1328
  /// Sparse prefetch packed SP FP with T1 hint to write using qword indices.
  | VSCATTERPF1QPS = 1329
  /// Scatter SP/DP FP elements in a vector to memory using qword indices.
  | VSCATTERQD = 1330
  /// Scatter packed double with signed qword indices.
  | VSCATTERQPD = 1331
  /// Scatter packed single with signed qword indices.
  | VSCATTERQPS = 1332
  /// Scatter SP/DP FP elements in a vector to memory using qword indices.
  | VSCATTERQQ = 1333
  /// Shuffle 128-bit lanes of a vector with 32 bit granular conditional update.
  | VSHUFF32X4 = 1334
  /// Shuffle 128-bit lanes of a vector with 64 bit granular conditional update.
  | VSHUFF64X2 = 1335
  /// Shuffle 128-bit lanes of a vector with 32 bit granular conditional update.
  | VSHUFI32X4 = 1336
  /// Shuffle 128-bit lanes of a vector with 64 bit granular conditional update.
  | VSHUFI64X2 = 1337
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | VSHUFPD = 1338
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | VSHUFPS = 1339
  /// Compute packed square roots of packed double-precision FP values.
  | VSQRTPD = 1340
  /// Compute square roots of packed single-precision floating-point values.
  | VSQRTPS = 1341
  /// Compute scalar square root of scalar double-precision FP values.
  | VSQRTSD = 1342
  /// Compute square root of scalar single-precision floating-point values.
  | VSQRTSS = 1343
  /// Subtract Packed Double-Precision Floating-Point Values.
  | VSUBPD = 1344
  /// Subtract Packed Single-Precision Floating-Point Values.
  | VSUBPS = 1345
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | VSUBSD = 1346
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | VSUBSS = 1347
  /// Packed Bit Test.
  | VTESTPD = 1348
  /// Packed Bit Test.
  | VTESTPS = 1349
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | VUCOMISD = 1350
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | VUCOMISS = 1351
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | VUNPCKHPD = 1352
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | VUNPCKHPS = 1353
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | VUNPCKLPD = 1354
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | VUNPCKLPS = 1355
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | VXORPD = 1356
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | VXORPS = 1357
  /// Zero Upper Bits of YMM Registers.
  | VZEROUPPER = 1358
  /// Wait.
  | WAIT = 1359
  /// Write Back and Invalidate Cache.
  | WBINVD = 1360
  /// Write FS Segment Base.
  | WRFSBASE = 1361
  /// Write GS Segment Base.
  | WRGSBASE = 1362
  /// Write to Model Specific Register.
  | WRMSR = 1363
  /// Write Data to User Page Key Register.
  | WRPKRU = 1364
  /// Write to a shadow stack.
  | WRSSD = 1365
  /// Write to a shadow stack.
  | WRSSQ = 1366
  /// Write to a user mode shadow stack.
  | WRUSSD = 1367
  /// Write to a user mode shadow stack.
  | WRUSSQ = 1368
  /// Transactional Abort.
  | XABORT = 1369
  /// Prefix hint to the beginning of an HLE transaction region.
  | XACQUIRE = 1370
  /// Exchange and Add.
  | XADD = 1371
  /// Transactional Begin.
  | XBEGIN = 1372
  /// Exchange Register/Memory with Register.
  | XCHG = 1373
  /// Transactional End.
  | XEND = 1374
  /// Value of Extended Control Register.
  | XGETBV = 1375
  /// Table lookup translation.
  | XLAT = 1376
  /// Table Look-up Translation.
  | XLATB = 1377
  /// Logical Exclusive OR.
  | XOR = 1378
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | XORPD = 1379
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | XORPS = 1380
  /// Prefix hint to the end of an HLE transaction region.
  | XRELEASE = 1381
  /// Restore Processor Extended States.
  | XRSTOR = 1382
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS = 1383
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS64 = 1384
  /// Save Processor Extended States.
  | XSAVE = 1385
  /// Save processor extended states with compaction to memory.
  | XSAVEC = 1386
  /// Save processor extended states with compaction to memory.
  | XSAVEC64 = 1387
  /// Save Processor Extended States Optimized.
  | XSAVEOPT = 1388
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES = 1389
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES64 = 1390
  /// Set Extended Control Register.
  | XSETBV = 1391
  /// Test If In Transactional Execution.
  | XTEST = 1392
  /// Invalid Opcode.
  | InvalOP = 1393

// vim: set tw=80 sts=2 sw=2:
