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

namespace B2R2.FrontEnd.BinLifter.Intel

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
  /// Complement Carry Flag.
  | CMC = 64
  /// Conditional Move (Move if above (CF = 0 and ZF = 0)).
  | CMOVA = 65
  /// Conditional Move (Move if above or equal (CF = 0)).
  | CMOVAE = 66
  /// Conditional Move (Move if below (CF = 1)).
  | CMOVB = 67
  /// Conditional Move (Move if below or equal (CF = 1 or ZF = 1)).
  | CMOVBE = 68
  /// Conditional move if carry.
  | CMOVC = 69
  /// Conditional Move (Move if greater (ZF = 0 and SF = OF)).
  | CMOVG = 70
  /// Conditional Move (Move if greater or equal (SF = OF)).
  | CMOVGE = 71
  /// Conditional Move (Move if less (SF <> OF)).
  | CMOVL = 72
  /// Conditional Move (Move if less or equal (ZF = 1 or SF <> OF)).
  | CMOVLE = 73
  /// Conditional move if not carry.
  | CMOVNC = 74
  /// Conditional Move (Move if not overflow (OF = 0)).
  | CMOVNO = 75
  /// Conditional Move (Move if not parity (PF = 0)).
  | CMOVNP = 76
  /// Conditional Move (Move if not sign (SF = 0)).
  | CMOVNS = 77
  /// Conditional Move (Move if not zero (ZF = 0)).
  | CMOVNZ = 78
  /// Conditional Move (Move if overflow (OF = 1)).
  | CMOVO = 79
  /// Conditional Move (Move if parity (PF = 1)).
  | CMOVP = 80
  /// Conditional Move (Move if sign (SF = 1)).
  | CMOVS = 81
  /// Conditional Move (Move if zero (ZF = 1)).
  | CMOVZ = 82
  /// Compare Two Operands.
  | CMP = 83
  /// Compare packed double-precision floating-point values.
  | CMPPD = 84
  /// Compare packed single-precision floating-point values.
  | CMPPS = 85
  /// Compare String Operands (byte).
  | CMPSB = 86
  /// Compare String Operands (dword) or Compare scalar dbl-precision FP values.
  | CMPSD = 87
  /// Compare String Operands (quadword).
  | CMPSQ = 88
  /// Compare scalar single-precision floating-point values.
  | CMPSS = 89
  /// Compare String Operands (word).
  | CMPSW = 90
  /// Compare and Exchange.
  | CMPXCHG = 91
  /// Compare and Exchange Bytes.
  | CMPXCHG16B = 92
  /// Compare and Exchange Bytes.
  | CMPXCHG8B = 93
  /// Compare Scalar Ordered Double-Precision FP Values and Set EFLAGS.
  | COMISD = 94
  /// Compare Scalar Ordered Single-Precision FP Values and Set EFLAGS.
  | COMISS = 95
  /// CPU Identification.
  | CPUID = 96
  /// Convert Quadword to Octaword.
  | CQO = 97
  /// Accumulate CRC32 Value.
  | CRC32 = 98
  /// Convert Packed Dword Integers to Packed Double-Precision FP Values.
  | CVTDQ2PD = 99
  /// Convert Packed Dword Integers to Packed Single-Precision FP Values.
  | CVTDQ2PS = 100
  /// Convert Packed Double-Precision FP Values to Packed Dword Integers.
  | CVTPD2DQ = 101
  /// Convert Packed Double-Precision FP Values to Packed Dword Integers.
  | CVTPD2PI = 102
  /// Convert Packed Double-Precision FP Values to Packed Single-Precision FP.
  | CVTPD2PS = 103
  /// Convert Packed Dword Integers to Packed Double-Precision FP Values.
  | CVTPI2PD = 104
  /// Convert Packed Dword Integers to Packed Single-Precision FP Values.
  | CVTPI2PS = 105
  /// Convert Packed Single-Precision FP Values to Packed Dword Integers.
  | CVTPS2DQ = 106
  /// Convert Packed Single-Precision FP Values to Packed Double-Precision FP.
  | CVTPS2PD = 107
  /// Convert Packed Single-Precision FP Values to Packed Dword Integers.
  | CVTPS2PI = 108
  /// Convert Scalar Double-Precision FP Value to Integer.
  | CVTSD2SI = 109
  /// Convert Scalar Double-Precision FP Value to Scalar Single-Precision FP.
  | CVTSD2SS = 110
  /// Convert Dword Integer to Scalar Double-Precision FP Value.
  | CVTSI2SD = 111
  /// Convert Dword Integer to Scalar Single-Precision FP Value.
  | CVTSI2SS = 112
  /// Convert Scalar Single-Precision FP Value to Scalar Double-Precision FP.
  | CVTSS2SD = 113
  /// Convert Scalar Single-Precision FP Value to Dword Integer.
  | CVTSS2SI = 114
  /// Convert with Truncation Packed Double-Precision FP Values to Packed Dword.
  | CVTTPD2DQ = 115
  /// Convert with Truncation Packed Double-Precision FP Values to Packed Dword.
  | CVTTPD2PI = 116
  /// Convert with Truncation Packed Single-Precision FP Values to Packed Dword.
  | CVTTPS2DQ = 117
  /// Convert with Truncation Packed Single-Precision FP Values to Packed Dword.
  | CVTTPS2PI = 118
  /// Convert with Truncation Scalar Double-Precision FP Value to Signed.
  | CVTTSD2SI = 119
  /// Convert with Truncation Scalar Single-Precision FP Value to Dword Integer.
  | CVTTSS2SI = 120
  /// Convert Word to Doubleword.
  | CWD = 121
  /// Convert Word to Doubleword.
  | CWDE = 122
  /// Decimal Adjust AL after Addition.
  | DAA = 123
  /// Decimal Adjust AL after Subtraction.
  | DAS = 124
  /// Decrement by 1.
  | DEC = 125
  /// Unsigned Divide.
  | DIV = 126
  /// Divide Packed Double-Precision Floating-Point Values.
  | DIVPD = 127
  /// Divide Packed Single-Precision Floating-Point Values.
  | DIVPS = 128
  /// Divide Scalar Double-Precision Floating-Point Values.
  | DIVSD = 129
  /// Divide Scalar Single-Precision Floating-Point Values.
  | DIVSS = 130
  /// Perform double-precision dot product for up to 2 elements and broadcast.
  | DPPD = 131
  /// Perform single-precision dot products for up to 4 elements and broadcast.
  | DPPS = 132
  /// Empty MMX Technology State.
  | EMMS = 133
  /// Execute an Enclave System Function of Specified Leaf Number.
  | ENCLS = 134
  /// Execute an Enclave User Function of Specified Leaf Number.
  | ENCLU = 135
  /// Terminate an Indirect Branch in 32-bit and Compatibility Mode.
  | ENDBR32 = 136
  /// Terminate an Indirect Branch in 64-bit Mode.
  | ENDBR64 = 137
  /// Make Stack Frame for Procedure Parameters.
  | ENTER = 138
  /// Extract Packed Floating-Point Values.
  | EXTRACTPS = 139
  /// Extract Field from Register.
  | EXTRQ = 140
  /// Compute 2x-1.
  | F2XM1 = 141
  /// Absolute Value.
  | FABS = 142
  /// Add.
  | FADD = 143
  /// Add and pop the register stack.
  | FADDP = 144
  /// Load Binary Coded Decimal.
  | FBLD = 145
  /// Store BCD Integer and Pop.
  | FBSTP = 146
  /// Change Sign.
  | FCHS = 147
  /// Clear Exceptions.
  | FCLEX = 148
  /// Floating-Point Conditional Move (if below (CF = 1)).
  | FCMOVB = 149
  /// Floating-Point Conditional Move (if below or equal (CF = 1 or ZF = 1)).
  | FCMOVBE = 150
  /// Floating-Point Conditional Move (if equal (ZF = 1)).
  | FCMOVE = 151
  /// Floating-Point Conditional Move (if not below (CF = 0)).
  | FCMOVNB = 152
  /// FP Conditional Move (if not below or equal (CF = 0 and ZF = 0)).
  | FCMOVNBE = 153
  /// Floating-Point Conditional Move (if not equal (ZF = 0)).
  | FCMOVNE = 154
  /// Floating-Point Conditional Move (if not unordered (PF = 0)).
  | FCMOVNU = 155
  /// Floating-Point Conditional Move (if unordered (PF = 1)).
  | FCMOVU = 156
  /// Compare Floating Point Values.
  | FCOM = 157
  /// Compare Floating Point Values and Set EFLAGS.
  | FCOMI = 158
  /// Compare Floating Point Values and Set EFLAGS.
  | FCOMIP = 159
  /// Compare Floating Point Values and pop register stack.
  | FCOMP = 160
  /// Compare Floating Point Values and pop register stack twice.
  | FCOMPP = 161
  /// Cosine.
  | FCOS = 162
  /// Decrement Stack-Top Pointer.
  | FDECSTP = 163
  /// Divide.
  | FDIV = 164
  /// Divide and pop the register stack.
  | FDIVP = 165
  /// Reverse Divide.
  | FDIVR = 166
  /// Reverse Divide and pop the register stack.
  | FDIVRP = 167
  /// Free Floating-Point Register.
  | FFREE = 168
  /// Performs FFREE ST(i) and pop stack.
  | FFREEP = 169
  /// Add.
  | FIADD = 170
  /// Compare Integer.
  | FICOM = 171
  /// Compare Integer and pop the register stack.
  | FICOMP = 172
  /// Divide.
  | FIDIV = 173
  /// Reverse Divide.
  | FIDIVR = 174
  /// Load Integer.
  | FILD = 175
  /// Multiply.
  | FIMUL = 176
  /// Increment Stack-Top Pointer.
  | FINCSTP = 177
  /// Initialize Floating-Point Unit.
  | FINIT = 178
  /// Store Integer.
  | FIST = 179
  /// Store Integer and pop the register stack.
  | FISTP = 180
  /// Store Integer with Truncation.
  | FISTTP = 181
  /// Subtract.
  | FISUB = 182
  /// Reverse Subtract.
  | FISUBR = 183
  /// Load Floating Point Value.
  | FLD = 184
  /// Load Constant (Push +1.0 onto the FPU register stack).
  | FLD1 = 185
  /// Load x87 FPU Control Word.
  | FLDCW = 186
  /// Load x87 FPU Environment.
  | FLDENV = 187
  /// Load Constant (Push log2e onto the FPU register stack).
  | FLDL2E = 188
  /// Load Constant (Push log210 onto the FPU register stack).
  | FLDL2T = 189
  /// Load Constant (Push log102 onto the FPU register stack).
  | FLDLG2 = 190
  /// Load Constant (Push loge2 onto the FPU register stack).
  | FLDLN2 = 191
  /// Load Constant (Push Pi onto the FPU register stack).
  | FLDPI = 192
  /// Load Constant (Push +0.0 onto the FPU register stack).
  | FLDZ = 193
  /// Multiply.
  | FMUL = 194
  /// Multiply and pop the register stack.
  | FMULP = 195
  /// Clear FP exception flags without checking for error conditions.
  | FNCLEX = 196
  /// Initialize FPU without checking error conditions.
  | FNINIT = 197
  /// No Operation.
  | FNOP = 198
  /// Save FPU state without checking error conditions.
  | FNSAVE = 199
  /// Store x87 FPU Control Word.
  | FNSTCW = 200
  /// Store FPU environment without checking error conditions.
  | FNSTENV = 201
  /// Store FPU status word without checking error conditions.
  | FNSTSW = 202
  /// Partial Arctangent.
  | FPATAN = 203
  /// Partial Remainder.
  | FPREM = 204
  /// Partial Remainder.
  | FPREM1 = 205
  /// Partial Tangent.
  | FPTAN = 206
  /// Round to Integer.
  | FRNDINT = 207
  /// Restore x87 FPU State.
  | FRSTOR = 208
  /// Store x87 FPU State.
  | FSAVE = 209
  /// Scale.
  | FSCALE = 210
  /// Sine.
  | FSIN = 211
  /// Sine and Cosine.
  | FSINCOS = 212
  /// Square Root.
  | FSQRT = 213
  /// Store Floating Point Value.
  | FST = 214
  /// Store FPU control word after checking error conditions.
  | FSTCW = 215
  /// Store x87 FPU Environment.
  | FSTENV = 216
  /// Store Floating Point Value.
  | FSTP = 217
  /// Store x87 FPU Status Word.
  | FSTSW = 218
  /// Subtract.
  | FSUB = 219
  /// Subtract and pop register stack.
  | FSUBP = 220
  /// Reverse Subtract.
  | FSUBR = 221
  /// Reverse Subtract and pop register stack.
  | FSUBRP = 222
  /// TEST.
  | FTST = 223
  /// Unordered Compare Floating Point Values.
  | FUCOM = 224
  /// Compare Floating Point Values and Set EFLAGS.
  | FUCOMI = 225
  /// Compare Floating Point Values and Set EFLAGS and pop register stack.
  | FUCOMIP = 226
  /// Unordered Compare Floating Point Values.
  | FUCOMP = 227
  /// Unordered Compare Floating Point Values.
  | FUCOMPP = 228
  /// Wait for FPU.
  | FWAIT = 229
  /// Examine ModR/M.
  | FXAM = 230
  /// Exchange Register Contents.
  | FXCH = 231
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR = 232
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR64 = 233
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE = 234
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE64 = 235
  /// Extract Exponent and Significand.
  | FXTRACT = 236
  /// compute y * log2x.
  | FYL2X = 237
  /// compute y * log2(x+1).
  | FYL2XP1 = 238
  /// GETSEC.
  | GETSEC = 239
  /// Galois Field Affine Transformation Inverse.
  | GF2P8AFFINEINVQB = 240
  /// Galois Field Affine Transformation.
  | GF2P8AFFINEQB = 241
  /// Galois Field Multiply Bytes.
  | GF2P8MULB = 242
  /// Packed Double-FP Horizontal Add.
  | HADDPD = 243
  /// Packed Single-FP Horizontal Add.
  | HADDPS = 244
  /// Halt.
  | HLT = 245
  /// Packed Double-FP Horizontal Subtract.
  | HSUBPD = 246
  /// Packed Single-FP Horizontal Subtract.
  | HSUBPS = 247
  /// Signed Divide.
  | IDIV = 248
  /// Signed Multiply.
  | IMUL = 249
  /// Input from Port.
  | IN = 250
  /// Increment by 1.
  | INC = 251
  /// Increment the shadow stack pointer (SSP).
  | INCSSPD = 252
  /// Increment the shadow stack pointer (SSP).
  | INCSSPQ = 253
  /// Input from Port to String.
  | INS = 254
  /// Input from Port to String (byte).
  | INSB = 255
  /// Input from Port to String (doubleword).
  | INSD = 256
  /// Insert Scalar Single-Precision Floating-Point Value.
  | INSERTPS = 257
  /// Inserts Field from a source Register to a destination Register.
  | INSERTQ = 258
  /// Input from Port to String (word).
  | INSW = 259
  /// Call to Interrupt (Interrupt vector specified by immediate byte).
  | INT = 260
  /// Call to Interrupt (Interrupt 3-trap to debugger).
  | INT3 = 261
  /// Call to Interrupt (InteInterrupt 4-if overflow flag is 1).
  | INTO = 262
  /// Invalidate Internal Caches.
  | INVD = 263
  /// Invalidate Translations Derived from EPT.
  | INVEPT = 264
  /// Invalidate TLB Entries.
  | INVLPG = 265
  /// Invalidate Process-Context Identifier.
  | INVPCID = 266
  /// Invalidate Translations Based on VPID.
  | INVVPID = 267
  /// Return from interrupt.
  | IRET = 268
  /// Interrupt return (32-bit operand size).
  | IRETD = 269
  /// Interrupt return (64-bit operand size).
  | IRETQ = 270
  /// Interrupt return (16-bit operand size).
  | IRETW = 271
  /// Jump if Condition Is Met (Jump near if not below, CF = 0).
  | JAE = 272
  | JNC = 272
  | JNB = 272
  /// Jump if Condition Is Met (Jump short if below, CF = 1).
  | JC = 273
  | JNAE = 273
  | JB = 273
  /// Jump if Condition Is Met (Jump short if CX register is 0).
  | JCXZ = 274
  /// Jump if Condition Is Met (Jump short if ECX register is 0).
  | JECXZ = 275
  /// Jump if Condition Is Met (Jump near if not less, SF = OF).
  | JGE = 276
  | JNL = 276
  /// Far jmp.
  | JMPFar = 277
  /// Near jmp.
  | JMPNear = 278
  /// Jump if Condition Is Met (Jump short if below or equal, CF = 1 or ZF).
  | JNA = 279
  | JBE = 279
  /// Jump if Condition Is Met (Jump short if above, CF = 0 and ZF = 0).
  | JNBE = 280
  | JA = 280
  /// Jump if Cond Is Met (Jump short if less or equal, ZF = 1 or SF <> OF).
  | JNG = 281
  | JLE = 281
  /// Jump if Condition Is Met (Jump short if less, SF <> OF).
  | JNGE = 282
  | JL = 282
  /// Jump if Condition Is Met (Jump short if greater, ZF = 0 and SF = OF).
  | JNLE = 283
  | JG = 283
  /// Jump if Condition Is Met (Jump near if not overflow, OF = 0).
  | JNO = 284
  /// Jump if Condition Is Met (Jump near if not sign, SF = 0).
  | JNS = 285
  /// Jump if Condition Is Met (Jump near if not zero, ZF = 0).
  | JNZ = 286
  | JNE = 286
  /// Jump if Condition Is Met (Jump near if overflow, OF = 1).
  | JO = 287
  /// Jump if Condition Is Met (Jump near if parity, PF = 1).
  | JP = 288
  | JPE = 288
  /// Jump if Condition Is Met (Jump near if not parity, PF = 0).
  | JPO = 289
  | JNP = 289
  /// Jump if Condition Is Met (Jump short if RCX register is 0).
  | JRCXZ = 290
  /// Jump if Condition Is Met (Jump short if sign, SF = 1).
  | JS = 291
  /// Jump if Condition Is Met (Jump short if zero, ZF = 1).
  | JZ = 292
  | JE = 292
  /// Add two 8-bit opmasks.
  | KADDB = 293
  /// Add two 32-bit opmasks.
  | KADDD = 294
  /// Add two 64-bit opmasks.
  | KADDQ = 295
  /// Add two 16-bit opmasks.
  | KADDW = 296
  /// Logical AND two 8-bit opmasks.
  | KANDB = 297
  /// Logical AND two 32-bit opmasks.
  | KANDD = 298
  /// Logical AND NOT two 8-bit opmasks.
  | KANDNB = 299
  /// Logical AND NOT two 32-bit opmasks.
  | KANDND = 300
  /// Logical AND NOT two 64-bit opmasks.
  | KANDNQ = 301
  /// Logical AND NOT two 16-bit opmasks.
  | KANDNW = 302
  /// Logical AND two 64-bit opmasks.
  | KANDQ = 303
  /// Logical AND two 16-bit opmasks.
  | KANDW = 304
  /// Move from or move to opmask register of 8-bit data.
  | KMOVB = 305
  /// Move from or move to opmask register of 32-bit data.
  | KMOVD = 306
  /// Move from or move to opmask register of 64-bit data.
  | KMOVQ = 307
  /// Move from or move to opmask register of 16-bit data.
  | KMOVW = 308
  /// Bitwise NOT of two 8-bit opmasks.
  | KNOTB = 309
  /// Bitwise NOT of two 32-bit opmasks.
  | KNOTD = 310
  /// Bitwise NOT of two 64-bit opmasks.
  | KNOTQ = 311
  /// Bitwise NOT of two 16-bit opmasks.
  | KNOTW = 312
  /// Logical OR two 8-bit opmasks.
  | KORB = 313
  /// Logical OR two 32-bit opmasks.
  | KORD = 314
  /// Logical OR two 64-bit opmasks.
  | KORQ = 315
  /// Update EFLAGS according to the result of bitwise OR of two 8-bit opmasks.
  | KORTESTB = 316
  /// Update EFLAGS according to the result of bitwise OR of two 32-bit opmasks.
  | KORTESTD = 317
  /// Update EFLAGS according to the result of bitwise OR of two 64-bit opmasks.
  | KORTESTQ = 318
  /// Update EFLAGS according to the result of bitwise OR of two 16-bit opmasks.
  | KORTESTW = 319
  /// Logical OR two 16-bit opmasks.
  | KORW = 320
  /// Shift left 8-bitopmask by specified count.
  | KSHIFTLB = 321
  /// Shift left 32-bitopmask by specified count.
  | KSHIFTLD = 322
  /// Shift left 64-bitopmask by specified count.
  | KSHIFTLQ = 323
  /// Shift left 16-bitopmask by specified count.
  | KSHIFTLW = 324
  /// Shift right 8-bit opmask by specified count.
  | KSHIFTRB = 325
  /// Shift right 32-bit opmask by specified count.
  | KSHIFTRD = 326
  /// Shift right 64-bit opmask by specified count.
  | KSHIFTRQ = 327
  /// Shift right 16-bit opmask by specified count.
  | KSHIFTRW = 328
  /// Update EFLAGS according to result of bitwise TEST of two 8-bit opmasks.
  | KTESTB = 329
  /// Update EFLAGS according to result of bitwise TEST of two 32-bit opmasks.
  | KTESTD = 330
  /// Update EFLAGS according to result of bitwise TEST of two 64-bit opmasks.
  | KTESTQ = 331
  /// Update EFLAGS according to result of bitwise TEST of two 16-bit opmasks.
  | KTESTW = 332
  /// Unpack and interleave two 8-bit opmasks into 16-bit mask.
  | KUNPCKBW = 333
  /// Unpack and interleave two 32-bit opmasks into 64-bit mask.
  | KUNPCKDQ = 334
  /// Unpack and interleave two 16-bit opmasks into 32-bit mask.
  | KUNPCKWD = 335
  /// Bitwise logical XNOR of two 8-bit opmasks.
  | KXNORB = 336
  /// Bitwise logical XNOR of two 32-bit opmasks.
  | KXNORD = 337
  /// Bitwise logical XNOR of two 64-bit opmasks.
  | KXNORQ = 338
  /// Bitwise logical XNOR of two 16-bit opmasks.
  | KXNORW = 339
  /// Logical XOR of two 8-bit opmasks.
  | KXORB = 340
  /// Logical XOR of two 32-bit opmasks.
  | KXORD = 341
  /// Logical XOR of two 64-bit opmasks.
  | KXORQ = 342
  /// Logical XOR of two 16-bit opmasks.
  | KXORW = 343
  /// Load Status Flags into AH Register.
  | LAHF = 344
  /// Load Access Rights Byte.
  | LAR = 345
  /// Load Unaligned Integer 128 Bits.
  | LDDQU = 346
  /// Load MXCSR Register.
  | LDMXCSR = 347
  /// Load Far Pointer (DS).
  | LDS = 348
  /// Load Effective Address.
  | LEA = 349
  /// High Level Procedure Exit.
  | LEAVE = 350
  /// Load Far Pointer (ES).
  | LES = 351
  /// Load Fence.
  | LFENCE = 352
  /// Load Far Pointer (FS).
  | LFS = 353
  /// Load GlobalDescriptor Table Register.
  | LGDT = 354
  /// Load Far Pointer (GS).
  | LGS = 355
  /// Load Interrupt Descriptor Table Register.
  | LIDT = 356
  /// Load Local Descriptor Table Register.
  | LLDT = 357
  /// Load Machine Status Word.
  | LMSW = 358
  /// Assert LOCK# Signal Prefix.
  | LOCK = 359
  /// Load String (byte).
  | LODSB = 360
  /// Load String (doubleword).
  | LODSD = 361
  /// Load String (quadword).
  | LODSQ = 362
  /// Load String (word).
  | LODSW = 363
  /// Loop According to ECX Counter (count <> 0).
  | LOOP = 364
  /// Loop According to ECX Counter (count <> 0 and ZF = 1).
  | LOOPE = 365
  /// Loop According to ECX Counter (count <> 0 and ZF = 0).
  | LOOPNE = 366
  /// Load Segment Limit.
  | LSL = 367
  /// Load Far Pointer (SS).
  | LSS = 368
  /// Load Task Register.
  | LTR = 369
  /// the Number of Leading Zero Bits.
  | LZCNT = 370
  /// Store Selected Bytes of Double Quadword.
  | MASKMOVDQU = 371
  /// Store Selected Bytes of Quadword.
  | MASKMOVQ = 372
  /// Return Maximum Packed Double-Precision Floating-Point Values.
  | MAXPD = 373
  /// Return Maximum Packed Single-Precision Floating-Point Values.
  | MAXPS = 374
  /// Return Maximum Scalar Double-Precision Floating-Point Values.
  | MAXSD = 375
  /// Return Maximum Scalar Single-Precision Floating-Point Values.
  | MAXSS = 376
  /// Memory Fence.
  | MFENCE = 377
  /// Return Minimum Packed Double-Precision Floating-Point Values.
  | MINPD = 378
  /// Return Minimum Packed Single-Precision Floating-Point Values.
  | MINPS = 379
  /// Return Minimum Scalar Double-Precision Floating-Point Values.
  | MINSD = 380
  /// Return Minimum Scalar Single-Precision Floating-Point Values.
  | MINSS = 381
  /// Set Up Monitor Address.
  | MONITOR = 382
  /// MOV.
  | MOV = 383
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | MOVAPD = 384
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | MOVAPS = 385
  /// Move Data After Swapping Bytes.
  | MOVBE = 386
  /// Move Doubleword.
  | MOVD = 387
  /// Move One Double-FP and Duplicate.
  | MOVDDUP = 388
  /// Move Quadword from XMM to MMX Technology Register.
  | MOVDQ2Q = 389
  /// Move Aligned Double Quadword.
  | MOVDQA = 390
  /// Move Unaligned Double Quadword.
  | MOVDQU = 391
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | MOVHLPS = 392
  /// Move High Packed Double-Precision Floating-Point Value.
  | MOVHPD = 393
  /// Move High Packed Single-Precision Floating-Point Values.
  | MOVHPS = 394
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | MOVLHPS = 395
  /// Move Low Packed Double-Precision Floating-Point Value.
  | MOVLPD = 396
  /// Move Low Packed Single-Precision Floating-Point Values.
  | MOVLPS = 397
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | MOVMSKPD = 398
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | MOVMSKPS = 399
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQ = 400
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQA = 401
  /// Store Doubleword Using Non-Temporal Hint.
  | MOVNTI = 402
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPD = 403
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPS = 404
  /// Store of Quadword Using Non-Temporal Hint.
  | MOVNTQ = 405
  /// Move Quadword.
  | MOVQ = 406
  /// Move Quadword from MMX Technology to XMM Register.
  | MOVQ2DQ = 407
  /// Move Data from String to String (byte).
  | MOVSB = 408
  /// Move Data from String to String (doubleword).
  | MOVSD = 409
  /// Move Packed Single-FP High and Duplicate.
  | MOVSHDUP = 410
  /// Move Packed Single-FP Low and Duplicate.
  | MOVSLDUP = 411
  /// Move Data from String to String (quadword).
  | MOVSQ = 412
  /// Move Scalar Single-Precision Floating-Point Values.
  | MOVSS = 413
  /// Move Data from String to String (word).
  | MOVSW = 414
  /// Move with Sign-Extension.
  | MOVSX = 415
  /// Move with Sign-Extension (doubleword to quadword).
  | MOVSXD = 416
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | MOVUPD = 417
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | MOVUPS = 418
  /// Move with Zero-Extend.
  | MOVZX = 419
  /// Compute Multiple Packed Sums of Absolute Difference.
  | MPSADBW = 420
  /// Unsigned Multiply.
  | MUL = 421
  /// Multiply Packed Double-Precision Floating-Point Values.
  | MULPD = 422
  /// Multiply Packed Single-Precision Floating-Point Values.
  | MULPS = 423
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | MULSD = 424
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | MULSS = 425
  /// Unsigned multiply without affecting arithmetic flags.
  | MULX = 426
  /// Monitor Wait.
  | MWAIT = 427
  /// Two's Complement Negation.
  | NEG = 428
  /// No Operation.
  | NOP = 429
  /// One's Complement Negation.
  | NOT = 430
  /// Logical Inclusive OR.
  | OR = 431
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | ORPD = 432
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | ORPS = 433
  /// Output to Port.
  | OUT = 434
  /// Output String to Port.
  | OUTS = 435
  /// Output String to Port (byte).
  | OUTSB = 436
  /// Output String to Port (doubleword).
  | OUTSD = 437
  /// Output String to Port (word).
  | OUTSW = 438
  /// Computes the absolute value of each signed byte data element.
  | PABSB = 439
  /// Computes the absolute value of each signed 32-bit data element.
  | PABSD = 440
  /// Computes the absolute value of each signed 16-bit data element.
  | PABSW = 441
  /// Pack with Signed Saturation.
  | PACKSSDW = 442
  /// Pack with Signed Saturation.
  | PACKSSWB = 443
  /// Pack with Unsigned Saturation.
  | PACKUSDW = 444
  /// Pack with Unsigned Saturation.
  | PACKUSWB = 445
  /// Add Packed byte Integers.
  | PADDB = 446
  /// Add Packed Doubleword Integers.
  | PADDD = 447
  /// Add Packed Quadword Integers.
  | PADDQ = 448
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | PADDSB = 449
  /// Add Packed Signed Integers with Signed Saturation (word).
  | PADDSW = 450
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | PADDUSB = 451
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | PADDUSW = 452
  /// Add Packed word Integers.
  | PADDW = 453
  /// Packed Align Right.
  | PALIGNR = 454
  /// Logical AND.
  | PAND = 455
  /// Logical AND NOT.
  | PANDN = 456
  /// Spin Loop Hint.
  | PAUSE = 457
  /// Average Packed Integers (byte).
  | PAVGB = 458
  /// Average Packed Integers (word).
  | PAVGW = 459
  /// Variable Blend Packed Bytes.
  | PBLENDVB = 460
  /// Blend Packed Words.
  | PBLENDW = 461
  /// Perform carryless multiplication of two 64-bit numbers.
  | PCLMULQDQ = 462
  /// Compare Packed Data for Equal (byte).
  | PCMPEQB = 463
  /// Compare Packed Data for Equal (doubleword).
  | PCMPEQD = 464
  /// Compare Packed Data for Equal (quadword).
  | PCMPEQQ = 465
  /// Compare packed words for equal.
  | PCMPEQW = 466
  /// Packed Compare Explicit Length Strings, Return Index.
  | PCMPESTRI = 467
  /// Packed Compare Explicit Length Strings, Return Mask.
  | PCMPESTRM = 468
  /// Compare Packed Signed Integers for Greater Than (byte).
  | PCMPGTB = 469
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | PCMPGTD = 470
  /// Performs logical compare of greater-than on packed integer quadwords.
  | PCMPGTQ = 471
  /// Compare Packed Signed Integers for Greater Than (word).
  | PCMPGTW = 472
  /// Packed Compare Implicit Length Strings, Return Index.
  | PCMPISTRI = 473
  /// Packed Compare Implicit Length Strings, Return Mask.
  | PCMPISTRM = 474
  /// Parallel deposit of bits using a mask.
  | PDEP = 475
  /// Parallel extraction of bits using a mask.
  | PEXT = 476
  /// Extract Byte.
  | PEXTRB = 477
  /// Extract Dword.
  | PEXTRD = 478
  /// Extract Qword.
  | PEXTRQ = 479
  /// Extract Word.
  | PEXTRW = 480
  /// Packed Horizontal Add.
  | PHADDD = 481
  /// Packed Horizontal Add and Saturate.
  | PHADDSW = 482
  /// Packed Horizontal Add.
  | PHADDW = 483
  /// Packed Horizontal Word Minimum.
  | PHMINPOSUW = 484
  /// Packed Horizontal Subtract.
  | PHSUBD = 485
  /// Packed Horizontal Subtract and Saturate.
  | PHSUBSW = 486
  /// Packed Horizontal Subtract.
  | PHSUBW = 487
  /// Insert Byte.
  | PINSRB = 488
  /// Insert a dword value from 32-bit register or memory into an XMM register.
  | PINSRD = 489
  /// Insert a qword value from 64-bit register or memory into an XMM register.
  | PINSRQ = 490
  /// Insert Word.
  | PINSRW = 491
  /// Multiply and Add Packed Signed and Unsigned Bytes.
  | PMADDUBSW = 492
  /// Multiply and Add Packed Integers.
  | PMADDWD = 493
  /// Compare packed signed byte integers.
  | PMAXSB = 494
  /// Compare packed signed dword integers.
  | PMAXSD = 495
  /// Maximum of Packed Signed Word Integers.
  | PMAXSW = 496
  /// Maximum of Packed Unsigned Byte Integers.
  | PMAXUB = 497
  /// Compare packed unsigned dword integers.
  | PMAXUD = 498
  /// Compare packed unsigned word integers.
  | PMAXUW = 499
  /// Minimum of Packed Signed Byte Integers.
  | PMINSB = 500
  /// Compare packed signed dword integers.
  | PMINSD = 501
  /// Minimum of Packed Signed Word Integers.
  | PMINSW = 502
  /// Minimum of Packed Unsigned Byte Integers.
  | PMINUB = 503
  /// Minimum of Packed Dword Integers.
  | PMINUD = 504
  /// Compare packed unsigned word integers.
  | PMINUW = 505
  /// Move Byte Mask.
  | PMOVMSKB = 506
  /// Packed Move with Sign Extend.
  | PMOVSXBD = 507
  /// Packed Move with Sign Extend.
  | PMOVSXBQ = 508
  /// Packed Move with Sign Extend.
  | PMOVSXBW = 509
  /// Packed Move with Sign Extend.
  | PMOVSXDQ = 510
  /// Packed Move with Sign Extend.
  | PMOVSXWD = 511
  /// Packed Move with Sign Extend.
  | PMOVSXWQ = 512
  /// Packed Move with Zero Extend.
  | PMOVZXBD = 513
  /// Packed Move with Zero Extend.
  | PMOVZXBQ = 514
  /// Packed Move with Zero Extend.
  | PMOVZXBW = 515
  /// Packed Move with Zero Extend.
  | PMOVZXDQ = 516
  /// Packed Move with Zero Extend.
  | PMOVZXWD = 517
  /// Packed Move with Zero Extend.
  | PMOVZXWQ = 518
  /// Multiply Packed Doubleword Integers.
  | PMULDQ = 519
  /// Packed Multiply High with Round and Scale.
  | PMULHRSW = 520
  /// Multiply Packed Unsigned Integers and Store High Result.
  | PMULHUW = 521
  /// Multiply Packed Signed Integers and Store High Result.
  | PMULHW = 522
  /// Multiply Packed Integers and Store Low Result.
  | PMULLD = 523
  /// Multiply Packed Signed Integers and Store Low Result.
  | PMULLW = 524
  /// Multiply Packed Unsigned Doubleword Integers.
  | PMULUDQ = 525
  /// Pop a Value from the Stack.
  | POP = 526
  /// Pop All General-Purpose Registers (word).
  | POPA = 527
  /// Pop All General-Purpose Registers (doubleword).
  | POPAD = 528
  /// Return the Count of Number of Bits Set to 1.
  | POPCNT = 529
  /// Pop Stack into EFLAGS Register (lower 16bits EFLAGS).
  | POPF = 530
  /// Pop Stack into EFLAGS Register (EFLAGS).
  | POPFD = 531
  /// Pop Stack into EFLAGS Register (RFLAGS).
  | POPFQ = 532
  /// Bitwise Logical OR.
  | POR = 533
  /// Prefetch Data Into Caches (using NTA hint).
  | PREFETCHNTA = 534
  /// Prefetch Data Into Caches (using T0 hint).
  | PREFETCHT0 = 535
  /// Prefetch Data Into Caches (using T1 hint).
  | PREFETCHT1 = 536
  /// Prefetch Data Into Caches (using T2 hint).
  | PREFETCHT2 = 537
  /// Prefetch Data into Caches in Anticipation of a Write.
  | PREFETCHW = 538
  /// Prefetch Vector Data Into Caches with Intent to Write and T1 Hint.
  | PREFETCHWT1 = 539
  /// Compute Sum of Absolute Differences.
  | PSADBW = 540
  /// Packed Shuffle Bytes.
  | PSHUFB = 541
  /// Shuffle Packed Doublewords.
  | PSHUFD = 542
  /// Shuffle Packed High Words.
  | PSHUFHW = 543
  /// Shuffle Packed Low Words.
  | PSHUFLW = 544
  /// Shuffle Packed Words.
  | PSHUFW = 545
  /// Packed Sign Byte.
  | PSIGNB = 546
  /// Packed Sign Doubleword.
  | PSIGND = 547
  /// Packed Sign Word.
  | PSIGNW = 548
  /// Shift Packed Data Left Logical (doubleword).
  | PSLLD = 549
  /// Shift Double Quadword Left Logical.
  | PSLLDQ = 550
  /// Shift Packed Data Left Logical (quadword).
  | PSLLQ = 551
  /// Shift Packed Data Left Logical (word).
  | PSLLW = 552
  /// Shift Packed Data Right Arithmetic (doubleword).
  | PSRAD = 553
  /// Shift Packed Data Right Arithmetic (word).
  | PSRAW = 554
  /// Shift Packed Data Right Logical (doubleword).
  | PSRLD = 555
  /// Shift Double Quadword Right Logical.
  | PSRLDQ = 556
  /// Shift Packed Data Right Logical (quadword).
  | PSRLQ = 557
  /// Shift Packed Data Right Logical (word).
  | PSRLW = 558
  /// Subtract Packed Integers (byte).
  | PSUBB = 559
  /// Subtract Packed Integers (doubleword).
  | PSUBD = 560
  /// Subtract Packed Integers (quadword).
  | PSUBQ = 561
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | PSUBSB = 562
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | PSUBSW = 563
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | PSUBUSB = 564
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | PSUBUSW = 565
  /// Subtract Packed Integers (word).
  | PSUBW = 566
  /// Logical Compare.
  | PTEST = 567
  /// Unpack High Data.
  | PUNPCKHBW = 568
  /// Unpack High Data.
  | PUNPCKHDQ = 569
  /// Unpack High Data.
  | PUNPCKHQDQ = 570
  /// Unpack High Data.
  | PUNPCKHWD = 571
  /// Unpack Low Data.
  | PUNPCKLBW = 572
  /// Unpack Low Data.
  | PUNPCKLDQ = 573
  /// Unpack Low Data.
  | PUNPCKLQDQ = 574
  /// Unpack Low Data.
  | PUNPCKLWD = 575
  /// Push Word, Doubleword or Quadword Onto the Stack.
  | PUSH = 576
  /// Push All General-Purpose Registers (word).
  | PUSHA = 577
  /// Push All General-Purpose Registers (doubleword).
  | PUSHAD = 578
  /// Push EFLAGS Register onto the Stack (16bits of EFLAGS).
  | PUSHF = 579
  /// Push EFLAGS Register onto the Stack (EFLAGS).
  | PUSHFD = 580
  /// Push EFLAGS Register onto the Stack (RFLAGS).
  | PUSHFQ = 581
  /// Logical Exclusive OR.
  | PXOR = 582
  /// Rotate x bits (CF, r/m(x)) left once.
  | RCL = 583
  /// Compute reciprocals of packed single-precision floating-point values.
  | RCPPS = 584
  /// Compute reciprocal of scalar single-precision floating-point values.
  | RCPSS = 585
  /// Rotate x bits (CF, r/m(x)) right once.
  | RCR = 586
  /// Read FS Segment Base.
  | RDFSBASE = 587
  /// Read GS Segment Base.
  | RDGSBASE = 588
  /// Read from Model Specific Register.
  | RDMSR = 589
  /// Read Protection Key Rights for User Pages.
  | RDPKRU = 590
  /// Read Performance-Monitoring Counters.
  | RDPMC = 591
  /// Read Random Number.
  | RDRAND = 592
  /// Read Random SEED.
  | RDSEED = 593
  /// Read shadow stack point (SSP).
  | RDSSPD = 594
  /// Read shadow stack point (SSP).
  | RDSSPQ = 595
  /// Read Time-Stamp Counter.
  | RDTSC = 596
  /// Read Time-Stamp Counter and Processor ID.
  | RDTSCP = 597
  /// Repeat while ECX not zero.
  | REP = 598
  /// Repeat while equal/Repeat while zero.
  | REPE = 599
  /// Repeat while not equal/Repeat while not zero.
  | REPNE = 600
  /// Repeat while not equal/Repeat while not zero.
  | REPNZ = 601
  /// Repeat while equal/Repeat while zero.
  | REPZ = 602
  /// Far return.
  | RETFar = 603
  /// Far return w/ immediate.
  | RETFarImm = 604
  /// Near return.
  | RETNear = 605
  /// Near return w/ immediate .
  | RETNearImm = 606
  /// Rotate x bits r/m(x) left once.
  | ROL = 607
  /// Rotate x bits r/m(x) right once.
  | ROR = 608
  /// Rotate right without affecting arithmetic flags.
  | RORX = 609
  /// Round Packed Double Precision Floating-Point Values.
  | ROUNDPD = 610
  /// Round Packed Single Precision Floating-Point Values.
  | ROUNDPS = 611
  /// Round Scalar Double Precision Floating-Point Values.
  | ROUNDSD = 612
  /// Round Scalar Single Precision Floating-Point Values.
  | ROUNDSS = 613
  /// Resume from System Management Mode.
  | RSM = 614
  /// Compute reciprocals of square roots of packed single-precision FP values.
  | RSQRTPS = 615
  /// Compute reciprocal of square root of scalar single-precision FP values.
  | RSQRTSS = 616
  /// Restore a shadow stack pointer (SSP).
  | RSTORSSP = 617
  /// Store AH into Flags.
  | SAHF = 618
  /// Shift.
  | SAR = 619
  /// Shift arithmetic right.
  | SARX = 620
  /// Save previous shadow stack pointer (SSP).
  | SAVEPREVSSP = 621
  /// Integer Subtraction with Borrow.
  | SBB = 622
  /// Scan String (byte).
  | SCASB = 623
  /// Scan String (doubleword).
  | SCASD = 624
  /// Scan String (quadword).
  | SCASQ = 625
  /// Scan String (word).
  | SCASW = 626
  /// Set byte if above (CF = 0 and ZF = 0).
  | SETA = 627
  /// Set byte if below (CF = 1).
  | SETB = 628
  /// Set byte if below or equal (CF = 1 or ZF = 1).
  | SETBE = 629
  /// Set byte if greater (ZF = 0 and SF = OF).
  | SETG = 630
  /// Set byte if less (SF <> OF).
  | SETL = 631
  /// Set byte if less or equal (ZF = 1 or SF <> OF).
  | SETLE = 632
  /// Set byte if not below (CF = 0).
  | SETNB = 633
  /// Set byte if not less (SF = OF).
  | SETNL = 634
  /// Set byte if not overflow (OF = 0).
  | SETNO = 635
  /// Set byte if not parity (PF = 0).
  | SETNP = 636
  /// Set byte if not sign (SF = 0).
  | SETNS = 637
  /// Set byte if not zero (ZF = 0).
  | SETNZ = 638
  /// Set byte if overflow (OF = 1).
  | SETO = 639
  /// Set byte if parity (PF = 1).
  | SETP = 640
  /// Set byte if sign (SF = 1).
  | SETS = 641
  /// Set busy bit in a supervisor shadow stack token.
  | SETSSBSY = 642
  /// Set byte if sign (ZF = 1).
  | SETZ = 643
  /// Store Fence.
  | SFENCE = 644
  /// Store Global Descriptor Table Register.
  | SGDT = 645
  /// Perform an Intermediate Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG1 = 646
  /// Perform a Final Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG2 = 647
  /// Calculate SHA1 state E after four rounds.
  | SHA1NEXTE = 648
  /// Perform four rounds of SHA1 operations.
  | SHA1RNDS4 = 649
  /// Perform an intermediate calculation for the next 4 SHA256 message dwords.
  | SHA256MSG1 = 650
  /// Perform the final calculation for the next four SHA256 message dwords.
  | SHA256MSG2 = 651
  /// Perform two rounds of SHA256 operations.
  | SHA256RNDS2 = 652
  /// Shift.
  | SHL = 653
  /// Double Precision Shift Left.
  | SHLD = 654
  /// Shift logic left.
  | SHLX = 655
  /// Shift.
  | SHR = 656
  /// Double Precision Shift Right.
  | SHRD = 657
  /// Shift logic right.
  | SHRX = 658
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | SHUFPD = 659
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | SHUFPS = 660
  /// Store Interrupt Descriptor Table Register.
  | SIDT = 661
  /// Store Local Descriptor Table Register.
  | SLDT = 662
  /// Store Machine Status Word.
  | SMSW = 663
  /// Compute packed square roots of packed double-precision FP values.
  | SQRTPD = 664
  /// Compute square roots of packed single-precision floating-point values.
  | SQRTPS = 665
  /// Compute scalar square root of scalar double-precision FP values.
  | SQRTSD = 666
  /// Compute square root of scalar single-precision floating-point values.
  | SQRTSS = 667
  /// Set AC Flag in EFLAGS Register.
  | STAC = 668
  /// Set Carry Flag.
  | STC = 669
  /// Set Direction Flag.
  | STD = 670
  /// Set Interrupt Flag.
  | STI = 671
  /// Store MXCSR Register State.
  | STMXCSR = 672
  /// Store String (store AL).
  | STOSB = 673
  /// Store String (store EAX).
  | STOSD = 674
  /// Store String (store RAX).
  | STOSQ = 675
  /// Store String (store AX).
  | STOSW = 676
  /// Store Task Register.
  | STR = 677
  /// Subtract.
  | SUB = 678
  /// Subtract Packed Double-Precision Floating-Point Values.
  | SUBPD = 679
  /// Subtract Packed Single-Precision Floating-Point Values.
  | SUBPS = 680
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | SUBSD = 681
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | SUBSS = 682
  /// Swap GS Base Register.
  | SWAPGS = 683
  /// Fast System Call.
  | SYSCALL = 684
  /// Fast System Call.
  | SYSENTER = 685
  /// Fast Return from Fast System Call.
  | SYSEXIT = 686
  /// Return From Fast System Call.
  | SYSRET = 687
  /// Logical Compare.
  | TEST = 688
  /// Count the Number of Trailing Zero Bits.
  | TZCNT = 689
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | UCOMISD = 690
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | UCOMISS = 691
  /// Undefined instruction.
  | UD = 692
  /// Undefined Instruction (Raise invalid opcode exception).
  | UD2 = 693
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | UNPCKHPD = 694
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | UNPCKHPS = 695
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | UNPCKLPD = 696
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | UNPCKLPS = 697
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPD = 698
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPS = 699
  /// Add Scalar Double-Precision Floating-Point Values.
  | VADDSD = 700
  /// Add Scalar Single-Precision Floating-Point Values.
  | VADDSS = 701
  /// Packed Double-FP Add/Subtract.
  | VADDSUBPD = 702
  /// Packed Single-FP Add/Subtract.
  | VADDSUBPS = 703
  /// Perform dword alignment of two concatenated source vectors.
  | VALIGND = 704
  /// Perform qword alignment of two concatenated source vectors.
  | VALIGNQ = 705
  /// Bitwise Logical AND of Packed Double-Precision Floating-Point Values.
  | VANDNPD = 706
  /// Bitwise Logical AND of Packed Single-Precision Floating-Point Values.
  | VANDNPS = 707
  /// Bitwise Logical AND NOT of Packed Double-Precision Floating-Point Values.
  | VANDPD = 708
  /// Bitwise Logical AND NOT of Packed Single-Precision Floating-Point Values.
  | VANDPS = 709
  /// Replace the VBLENDVPD instructions (using opmask as select control).
  | VBLENDMPD = 710
  /// Replace the VBLENDVPS instructions (using opmask as select control).
  | VBLENDMPS = 711
  /// Blend Packed Double-Precision Floats.
  | VBLENDPD = 712
  /// Blend Packed Single-Precision Floats.
  | VBLENDPS = 713
  /// Variable Blend Packed Double-Precision Floats.
  | VBLENDVPD = 714
  /// Variable Blend Packed Single-Precision Floats.
  | VBLENDVPS = 715
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTF128 = 716
  /// Broadcast 128 bits of int data in mem to low and high 128-bits in ymm1.
  | VBROADCASTI128 = 717
  /// Broadcast low double-precision floating-point element.
  | VBROADCASTSD = 718
  /// Broadcast Floating-Point Data.
  | VBROADCASTSS = 719
  /// Compare Packed Double-Precision Floating-Point Values.
  | VCMPPD = 720
  /// Compare Packed Single-Precision Floating-Point Values.
  | VCMPPS = 721
  /// Compare Scalar Double-Precision Floating-Point Values.
  | VCMPSD = 722
  /// Scalar Single-Precision Floating-Point Values.
  | VCMPSS = 723
  /// Compare Scalar Ordered Double-Precision FP Values and Set EFLAGS.
  | VCOMISD = 724
  /// Compare Scalar Ordered Single-Precision FP Values and Set EFLAGS.
  | VCOMISS = 725
  /// Compress packed DP elements of a vector.
  | VCOMPRESSPD = 726
  /// Compress packed SP elements of a vector.
  | VCOMPRESSPS = 727
  /// Convert two packed signed doubleword integers.
  | VCVTDQ2PD = 728
  /// Convert Packed Dword Integers to Packed Single-Precision FP Values.
  | VCVTDQ2PS = 729
  /// Convert two packed double-precision floating-point values.
  | VCVTPD2PS = 730
  /// Convert Packed Double-Precision FP Values to Packed Quadword Integers.
  | VCVTPD2QQ = 731
  /// Convert Packed DP FP Values to Packed Unsigned DWord Integers.
  | VCVTPD2UDQ = 732
  /// Convert Packed DP FP Values to Packed Unsigned QWord Integers.
  | VCVTPD2UQQ = 733
  /// Convert 16-bit FP values to Single-Precision FP values.
  | VCVTPH2PS = 734
  /// Conv Packed Single-Precision FP Values to Packed Dbl-Precision FP Values.
  | VCVTPS2PD = 735
  /// Convert Single-Precision FP value to 16-bit FP value.
  | VCVTPS2PH = 736
  /// Convert Packed SP FP Values to Packed Signed QWord Int Values.
  | VCVTPS2QQ = 737
  /// Convert Packed SP FP Values to Packed Unsigned DWord Int Values.
  | VCVTPS2UDQ = 738
  /// Convert Packed SP FP Values to Packed Unsigned QWord Int Values.
  | VCVTPS2UQQ = 739
  /// Convert Packed Quadword Integers to Packed Double-Precision FP Values.
  | VCVTQQ2PD = 740
  /// Convert Packed Quadword Integers to Packed Single-Precision FP Values.
  | VCVTQQ2PS = 741
  /// Convert Scalar Double-Precision FP Value to Integer.
  | VCVTSD2SI = 742
  /// Convert Scalar Double-Precision FP Val to Scalar Single-Precision FP Val.
  | VCVTSD2SS = 743
  /// Convert Scalar Double-Precision FP Value to Unsigned Doubleword Integer.
  | VCVTSD2USI = 744
  /// Convert Dword Integer to Scalar Double-Precision FP Value.
  | VCVTSI2SD = 745
  /// Convert Dword Integer to Scalar Single-Precision FP Value.
  | VCVTSI2SS = 746
  /// Convert Scalar Single-Precision FP Val to Scalar Double-Precision FP Val.
  | VCVTSS2SD = 747
  /// Convert Scalar Single-Precision FP Value to Dword Integer.
  | VCVTSS2SI = 748
  /// Convert Scalar Single-Precision FP Value to Unsigned Doubleword Integer.
  | VCVTSS2USI = 749
  /// Conv with Trunc Packed Double-Precision FP Val to Packed Dword Integers.
  | VCVTTPD2DQ = 750
  /// Convert with Truncation Packed DP FP Values to Packed QWord Integers.
  | VCVTTPD2QQ = 751
  /// Convert with Truncation Packed DP FP Values to Packed Unsigned DWord Int.
  | VCVTTPD2UDQ = 752
  /// Convert with Truncation Packed DP FP Values to Packed Unsigned QWord Int.
  | VCVTTPD2UQQ = 753
  /// Conv with Trunc Packed Single-Precision FP Val to Packed Dword Integers.
  | VCVTTPS2DQ = 754
  /// Convert with Truncation Packed SP FP Values to Packed Signed QWord Int.
  | VCVTTPS2QQ = 755
  /// Convert with Truncation Packed SP FP Values to Packed Unsigned DWord Int.
  | VCVTTPS2UDQ = 756
  /// Convert with Truncation Packed SP FP Values to Packed Unsigned QWord Int.
  | VCVTTPS2UQQ = 757
  /// Convert with Truncation Scalar Double-Precision FP Value to Signed.
  | VCVTTSD2SI = 758
  /// Convert with Truncation Scalar DP FP Value to Unsigned Integer.
  | VCVTTSD2USI = 759
  /// Convert with Truncation Scalar Single-Precision FP Value to Dword Integer.
  | VCVTTSS2SI = 760
  /// Convert with Truncation Scalar Single-Precision FP Value to Unsigned Int.
  | VCVTTSS2USI = 761
  /// Convert Packed Unsigned DWord Integers to Packed DP FP Values.
  | VCVTUDQ2PD = 762
  /// Convert Packed Unsigned DWord Integers to Packed SP FP Values.
  | VCVTUDQ2PS = 763
  /// Convert Packed Unsigned QWord Integers to Packed DP FP Values.
  | VCVTUQQ2PD = 764
  /// Convert Packed Unsigned QWord Integers to Packed SP FP Values.
  | VCVTUQQ2PS = 765
  /// Convert an unsigned integer to the low DP FP elem and merge to a vector.
  | VCVTUSI2USD = 766
  /// Convert an unsigned integer to the low SP FP elem and merge to a vector.
  | VCVTUSI2USS = 767
  /// Double Block Packed Sum-Absolute-Differences (SAD) on Unsigned Bytes.
  | VDBPSADBW = 768
  /// Divide Packed Double-Precision Floating-Point Values.
  | VDIVPD = 769
  /// Divide Packed Single-Precision Floating-Point Values.
  | VDIVPS = 770
  /// Divide Scalar Double-Precision Floating-Point Values.
  | VDIVSD = 771
  /// Divide Scalar Single-Precision Floating-Point Values.
  | VDIVSS = 772
  /// Verify a Segment for Reading.
  | VERR = 773
  /// Verify a Segment for Writing.
  | VERW = 774
  /// Compute approximate base-2 exponential of packed DP FP elems of a vector.
  | VEXP2PD = 775
  /// Compute approximate base-2 exponential of packed SP FP elems of a vector.
  | VEXP2PS = 776
  /// Compute approximate base-2 exponential of the low DP FP elem of a vector.
  | VEXP2SD = 777
  /// Compute approximate base-2 exponential of the low SP FP elem of a vector.
  | VEXP2SS = 778
  /// Load Sparse Packed Double-Precision FP Values from Dense Memory.
  | VEXPANDPD = 779
  /// Load Sparse Packed Single-Precision FP Values from Dense Memory.
  | VEXPANDPS = 780
  /// Extract Packed Floating-Point Values.
  | VEXTRACTF128 = 781
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTF32X4 = 782
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTF32X8 = 783
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTF64X2 = 784
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTF64X4 = 785
  /// Extract packed Integer Values.
  | VEXTRACTI128 = 786
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTI32X4 = 787
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTI32X8 = 788
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTI64X2 = 789
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTI64X4 = 790
  /// Extract From Packed Single-Precision Floats.
  | VEXTRACTPS = 791
  /// Fix Up Special Packed Float64 Values.
  | VFIXUPIMMPD = 792
  /// Fix Up Special Packed Float32 Values.
  | VFIXUPIMMPS = 793
  /// Fix Up Special Scalar Float64 Value.
  | VFIXUPIMMSD = 794
  /// Fix Up Special Scalar Float32 Value.
  | VFIXUPIMMSS = 795
  /// Fused Multiply-Add of Packed Double-Precision Floating-Point Values.
  | VFMADD132PD = 796
  /// Fused Multiply-Add of Packed Single-Precision Floating-Point Values.
  | VFMADD132PS = 797
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD132SD = 798
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD132SS = 799
  /// Fused Multiply-Add of Packed Double-Precision Floating-Point Values.
  | VFMADD213PD = 800
  /// Fused Multiply-Add of Packed Single-Precision Floating-Point Values.
  | VFMADD213PS = 801
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD213SD = 802
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD213SS = 803
  /// Fused Multiply-Add of Packed Double-Precision Floating-Point Value.
  | VFMADD231PD = 804
  /// Fused Multiply-Add of Packed Single-Precision Floating-Point Values.
  | VFMADD231PS = 805
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD231SD = 806
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD231SS = 807
  /// Fused Multiply-Alternating Add/Sub of Packed Double-Precision FP Values.
  | VFMADDSUB213PD = 808
  /// Fused Multiply-Alternating Add/Sub of Packed Single-Precision FP Values.
  | VFMADDSUB213PS = 809
  /// Fused Multiply-Alternating Add/Sub of Packed Double-Precision FP Values.
  | VFMADDSUB231PD = 810
  /// Fused Multiply-Alternating Add/Sub of Packed Single-Precision FP Values.
  | VFMADDSUB231PS = 811
  /// Fused Multiply-Subtract of Packed Double-Precision Floating-Point Values.
  | VFMSUB132PD = 812
  /// Fused Multiply-Subtract of Packed Single-Precision Floating-Point Values.
  | VFMSUB132PS = 813
  /// Fused Multiply-Subtract of Scalar Double-Precision Floating-Point Values.
  | VFMSUB132SD = 814
  /// Fused Multiply-Subtract of Scalar Single-Precision Floating-Point Values.
  | VFMSUB132SS = 815
  /// Fused Multiply-Subtract of Packed Double-Precision Floating-Point Values.
  | VFMSUB213PD = 816
  /// Fused Multiply-Subtract of Packed Single-Precision Floating-Point Values.
  | VFMSUB213PS = 817
  /// Fused Multiply-Subtract of Scalar Double-Precision Floating-Point Values.
  | VFMSUB213SD = 818
  /// Fused Multiply-Subtract of Scalar Single-Precision Floating-Point Values.
  | VFMSUB213SS = 819
  /// Fused Multiply-Subtract of Packed Double-Precision Floating-Point Values.
  | VFMSUB231PD = 820
  /// Fused Multiply-Subtract of Packed Single-Precision Floating-Point Values.
  | VFMSUB231PS = 821
  /// Fused Multiply-Subtract of Scalar Double-Precision Floating-Point Values.
  | VFMSUB231SD = 822
  /// Fused Multiply-Subtract of Scalar Single-Precision Floating-Point Values.
  | VFMSUB231SS = 823
  /// Fused Multiply-Alternating Sub/Add of Packed Double-Precision FP Values.
  | VFMSUBADD213PD = 824
  /// Fused Multiply-Alternating Sub/Add of Packed Single-Precision FP Values.
  | VFMSUBADD213PS = 825
  /// Fused Multiply-Alternating Sub/Add of Packed Double-Precision FP Values.
  | VFMSUBADD231PD = 826
  /// Fused Multiply-Alternating Sub/Add of Packed Single-Precision FP Values.
  | VFMSUBADD231PS = 827
  /// Fused Negative Multiply-Add of Packed Double-Precision FP Values.
  | VFNMADD132PD = 828
  /// Fused Negative Mul-Add of Packed Single-Precision Floating-Point Values.
  | VFNMADD132PS = 829
  /// Fused Negative Multiply-Add of Scalar Double-Precision FP Values.
  | VFNMADD132SD = 830
  /// Fused Negative Mul-Add of Scalar Single-Precision Floating-Point Values.
  | VFNMADD132SS = 831
  /// Fused Negative Multiply-Add of Packed Double-Precision FP Values.
  | VFNMADD213PD = 832
  /// Fused Negative Mul-Add of Packed Single-Precision Floating-Point Values.
  | VFNMADD213PS = 833
  /// Fused Negative Multiply-Add of Scalar Double-Precision FP Values.
  | VFNMADD213SD = 834
  /// Fused Negative Mul-Add of Scalar Single-Precision Floating-Point Values.
  | VFNMADD213SS = 835
  /// Fused Negative Multiply-Add of Packed Double-Precision FP Values.
  | VFNMADD231PD = 836
  /// Fused Negative Mul-Add of Packed Single-Precision Floating-Point Values.
  | VFNMADD231PS = 837
  /// Fused Negative Multiply-Add of Scalar Double-Precision FP Values.
  | VFNMADD231SD = 838
  /// Fused Negative Mul-Add of Scalar Single-Precision Floating-Point Values.
  | VFNMADD231SS = 839
  /// Fused Negative Multiply-Subtract of Packed Double-Precision FP Values.
  | VFNMSUB132PD = 840
  /// Fused Negative Multiply-Subtract of Packed Single-Precision FP Values.
  | VFNMSUB132PS = 841
  /// Fused Negative Multiply-Subtract of Scalar Double-Precision FP Values.
  | VFNMSUB132SD = 842
  /// Fused Negative Multiply-Subtract of Scalar Single-Precision FP Values.
  | VFNMSUB132SS = 843
  /// Fused Negative Multiply-Subtract of Packed Double-Precision FP Values.
  | VFNMSUB213PD = 844
  /// Fused Negative Multiply-Subtract of Packed Single-Precision FP Values.
  | VFNMSUB213PS = 845
  /// Fused Negative Multiply-Subtract of Scalar Double-Precision FP Values.
  | VFNMSUB213SD = 846
  /// Fused Negative Multiply-Subtract of Scalar Single-Precision FP Values.
  | VFNMSUB213SS = 847
  /// Fused Negative Multiply-Subtract of Packed Double-Precision FP Values.
  | VFNMSUB231PD = 848
  /// Fused Negative Multiply-Subtract of Packed Single-Precision FP Values.
  | VFNMSUB231PS = 849
  /// Fused Negative Multiply-Subtract of Scalar Double-Precision FP Values.
  | VFNMSUB231SD = 850
  /// Fused Negative Multiply-Subtract of Scalar Single-Precision FP Values.
  | VFNMSUB231SS = 851
  /// Tests Types Of a Packed Float64 Values.
  | VFPCLASSPD = 852
  /// Tests Types Of a Packed Float32 Values.
  | VFPCLASSPS = 853
  /// Tests Types Of a Scalar Float64 Values.
  | VFPCLASSSD = 854
  /// Tests Types Of a Scalar Float32 Values.
  | VFPCLASSSS = 855
  /// Gather Packed SP FP values Using Signed Dword/Qword Indices.
  | VGATHERDPS = 856
  /// Gather Packed DP FP Values Using Signed Dword/Qword Indices.
  | VGATHERQPD = 857
  /// Convert Exponents of Packed DP FP Values to DP FP Values.
  | VGETEXPPD = 858
  /// Convert Exponents of Packed SP FP Values to SP FP Values.
  | VGETEXPPS = 859
  /// Convert Exponents of Scalar DP FP Values to DP FP Value.
  | VGETEXPSD = 860
  /// Convert Exponents of Scalar SP FP Values to SP FP Value.
  | VGETEXPSS = 861
  /// Extract Float64 Vector of Normalized Mantissas from Float64 Vector.
  | VGETMANTPD = 862
  /// Extract Float32 Vector of Normalized Mantissas from Float32 Vector.
  | VGETMANTPS = 863
  /// Extract Float64 of Normalized Mantissas from Float64 Scalar.
  | VGETMANTSD = 864
  /// Extract Float32 Vector of Normalized Mantissa from Float32 Vector.
  | VGETMANTSS = 865
  /// Packed Double-FP Horizontal Add.
  | VHADDPD = 866
  /// Packed Single-FP Horizontal Add.
  | VHADDPS = 867
  /// Packed Double-FP Horizontal Subtract.
  | VHSUBPD = 868
  /// Packed Single-FP Horizontal Subtract.
  | VHSUBPS = 869
  /// Insert Packed Floating-Point Values.
  | VINSERTF128 = 870
  /// Insert Packed Floating-Point Values.
  | VINSERTF32X4 = 871
  /// Insert Packed Floating-Point Values.
  | VINSERTF64X2 = 872
  /// Insert Packed Floating-Point Values.
  | VINSERTF64X4 = 873
  /// Insert Packed Integer Values.
  | VINSERTI128 = 874
  /// Insert 256 bits of packed doubleword integer values.
  | VINSERTI32X8 = 875
  /// Insert Packed Floating-Point Values.
  | VINSERTI64X2 = 876
  /// Insert 256 bits of packed quadword integer values.
  | VINSERTI64X4 = 877
  /// Insert Into Packed Single-Precision Floats.
  | VINSERTPS = 878
  /// Load Unaligned Integer 128 Bits.
  | VLDDQU = 879
  /// Conditional SIMD Packed Loads and Stores.
  | VMASKMOVPD = 880
  /// Conditional SIMD Packed Loads and Stores.
  | VMASKMOVPS = 881
  /// Return Maximum Packed Double-Precision Floating-Point Values.
  | VMAXPD = 882
  /// Maximum of Packed Single-Precision Floating-Point Values.
  | VMAXPS = 883
  /// Return Maximum Scalar Double-Precision Floating-Point Value.
  | VMAXSD = 884
  /// Return Maximum Scalar Single-Precision Floating-Point Value.
  | VMAXSS = 885
  /// Call to VM Monitor.
  | VMCALL = 886
  /// Clear Virtual-Machine Control Structure.
  | VMCLEAR = 887
  /// Invoke VM function.
  | VMFUNC = 888
  /// Return Minimum Packed Double-Precision Floating-Point Values.
  | VMINPD = 889
  /// Return Minimum Packed Single-Precision Floating-Point Values.
  | VMINPS = 890
  /// Return Minimum Scalar Double-Precision Floating-Point Value.
  | VMINSD = 891
  /// Return Minimum Scalar Single-Precision Floating-Point Value.
  | VMINSS = 892
  /// Launch Virtual Machine.
  | VMLAUNCH = 893
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | VMOVAPD = 894
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | VMOVAPS = 895
  /// Move Doubleword.
  | VMOVD = 896
  /// Move One Double-FP and Duplicate.
  | VMOVDDUP = 897
  /// Move Aligned Double Quadword.
  | VMOVDQA = 898
  /// Move Aligned Double Quadword.
  | VMOVDQA32 = 899
  /// Move Aligned Double Quadword.
  | VMOVDQA64 = 900
  /// Move Unaligned Double Quadword.
  | VMOVDQU = 901
  /// VMOVDQU with 16-bit granular conditional update.
  | VMOVDQU16 = 902
  /// Move Unaligned Double Quadword.
  | VMOVDQU32 = 903
  /// Move Unaligned Double Quadword.
  | VMOVDQU64 = 904
  /// VMOVDQU with 8-bit granular conditional update.
  | VMOVDQU8 = 905
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | VMOVHLPS = 906
  /// Move High Packed Double-Precision Floating-Point Value.
  | VMOVHPD = 907
  /// Move High Packed Single-Precision Floating-Point Values.
  | VMOVHPS = 908
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | VMOVLHPS = 909
  /// Move Low Packed Double-Precision Floating-Point Value.
  | VMOVLPD = 910
  /// Move Low Packed Single-Precision Floating-Point Values.
  | VMOVLPS = 911
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | VMOVMSKPD = 912
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | VMOVMSKPS = 913
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | VMOVNTDQ = 914
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPD = 915
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPS = 916
  /// Move Quadword.
  | VMOVQ = 917
  /// Move Data from String to String (doubleword).
  | VMOVSD = 918
  /// Move Packed Single-FP High and Duplicate.
  | VMOVSHDUP = 919
  /// Move Packed Single-FP Low and Duplicate.
  | VMOVSLDUP = 920
  /// Move Scalar Single-Precision Floating-Point Values.
  | VMOVSS = 921
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | VMOVUPD = 922
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | VMOVUPS = 923
  /// Load Pointer to Virtual-Machine Control Structure.
  | VMPTRLD = 924
  /// Store Pointer to Virtual-Machine Control Structure.
  | VMPTRST = 925
  /// Reads a component from the VMCS and stores it into a destination operand.
  | VMREAD = 926
  /// Resume Virtual Machine.
  | VMRESUME = 927
  /// Multiply Packed Double-Precision Floating-Point Values.
  | VMULPD = 928
  /// Multiply Packed Single-Precision Floating-Point Values.
  | VMULPS = 929
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | VMULSD = 930
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | VMULSS = 931
  /// Writes a component to the VMCS from a source operand.
  | VMWRITE = 932
  /// Leave VMX Operation.
  | VMXOFF = 933
  /// Enter VMX Operation.
  | VMXON = 934
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | VORPD = 935
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | VORPS = 936
  /// Packed Absolute Value (byte).
  | VPABSB = 937
  /// Packed Absolute Value (dword).
  | VPABSD = 938
  /// Packed Absolute Value (word).
  | VPABSW = 939
  /// Pack with Signed Saturation.
  | VPACKSSDW = 940
  /// Pack with Signed Saturation.
  | VPACKSSWB = 941
  /// Pack with Unsigned Saturation.
  | VPACKUSDW = 942
  /// Pack with Unsigned Saturation.
  | VPACKUSWB = 943
  /// Add Packed byte Integers.
  | VPADDB = 944
  /// Add Packed Doubleword Integers.
  | VPADDD = 945
  /// Add Packed Quadword Integers.
  | VPADDQ = 946
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | VPADDSB = 947
  /// Add Packed Signed Integers with Signed Saturation (word).
  | VPADDSW = 948
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPADDUSB = 949
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | VPADDUSW = 950
  /// Add Packed word Integers.
  | VPADDW = 951
  /// Packed Align Right.
  | VPALIGNR = 952
  /// Logical AND.
  | VPAND = 953
  /// Logical AND NOT.
  | VPANDN = 954
  /// Average Packed Integers (byte).
  | VPAVGB = 955
  /// Average Packed Integers (word).
  | VPAVGW = 956
  /// Blend Packed Dwords.
  | VPBLENDD = 957
  /// Blend Byte/Word Vectors Using an Opmask Control.
  | VPBLENDMB = 958
  /// Blend Int32/Int64 Vectors Using an OpMask Control.
  | VPBLENDMD = 959
  /// Blend qword elements using opmask as select control.
  | VPBLENDMQ = 960
  /// Blend word elements using opmask as select control.
  | VPBLENDMW = 961
  /// Variable Blend Packed Bytes.
  | VPBLENDVB = 962
  /// Blend Packed Words.
  | VPBLENDW = 963
  /// Broadcast Integer Data.
  | VPBROADCASTB = 964
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTD = 965
  /// Broadcast Mask to Vector Register.
  | VPBROADCASTM = 966
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTQ = 967
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTW = 968
  /// Compare packed signed bytes using specified primitive.
  | VPCMPB = 969
  /// Compare packed signed dwords using specified primitive.
  | VPCMPD = 970
  /// Compare Packed Data for Equal (byte).
  | VPCMPEQB = 971
  /// Compare Packed Data for Equal (doubleword).
  | VPCMPEQD = 972
  /// Compare Packed Data for Equal (quadword).
  | VPCMPEQQ = 973
  /// Compare Packed Data for Equal (word).
  | VPCMPEQW = 974
  /// Packed Compare Explicit Length Strings, Return Index.
  | VPCMPESTRI = 975
  /// Packed Compare Explicit Length Strings, Return Mask.
  | VPCMPESTRM = 976
  /// Compare Packed Signed Integers for Greater Than (byte).
  | VPCMPGTB = 977
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | VPCMPGTD = 978
  /// Compare Packed Data for Greater Than (qword).
  | VPCMPGTQ = 979
  /// Compare Packed Signed Integers for Greater Than (word).
  | VPCMPGTW = 980
  /// Packed Compare Implicit Length Strings, Return Index.
  | VPCMPISTRI = 981
  /// Packed Compare Implicit Length Strings, Return Mask.
  | VPCMPISTRM = 982
  /// Compare packed signed quadwords using specified primitive.
  | VPCMPQ = 983
  /// Compare packed signed words using specified primitive.
  | VPCMPW = 984
  /// Compare packed unsigned bytes using specified primitive.
  | VPCMUB = 985
  /// Compare packed unsigned dwords using specified primitive.
  | VPCMUD = 986
  /// Compare packed unsigned quadwords using specified primitive.
  | VPCMUQ = 987
  /// Compare packed unsigned words using specified primitive.
  | VPCMUW = 988
  /// Store Sparse Packed Doubleword Integer Values into Dense Memory/Register.
  | VPCOMPRESSD = 989
  /// Store Sparse Packed Quadword Integer Values into Dense Memory/Register.
  | VPCOMPRESSQ = 990
  /// Detect conflicts within a vector of packed 32/64-bit integers.
  | VPCONFLICTD = 991
  /// Detect conflicts within a vector of packed 64-bit integers.
  | VPCONFLICTQ = 992
  /// Permute Floating-Point Values.
  | VPERM2F128 = 993
  /// Permute Integer Values.
  | VPERM2I128 = 994
  /// Permute Packed Doublewords/Words Elements.
  | VPERMD = 995
  /// Full Permute of Bytes from Two Tables Overwriting the Index.
  | VPERMI2B = 996
  /// Full permute of two tables of dword elements overwriting the index vector.
  | VPERMI2D = 997
  /// Full permute of two tables of DP elements overwriting the index vector.
  | VPERMI2PD = 998
  /// Full permute of two tables of SP elements overwriting the index vector.
  | VPERMI2PS = 999
  /// Full permute of two tables of qword elements overwriting the index vector.
  | VPERMI2Q = 1000
  /// Full Permute From Two Tables Overwriting the Index.
  | VPERMI2W = 1001
  /// Permute Double-Precision Floating-Point Values.
  | VPERMILPD = 1002
  /// Permute Single-Precision Floating-Point Values.
  | VPERMILPS = 1003
  /// Permute Double-Precision Floating-Point Elements.
  | VPERMPD = 1004
  /// Permute Single-Precision Floating-Point Elements.
  | VPERMPS = 1005
  /// Qwords Element Permutation.
  | VPERMQ = 1006
  /// Full permute of two tables of dword elements overwriting one source table.
  | VPERMT2D = 1007
  /// Full permute of two tables of DP elements overwriting one source table.
  | VPERMT2PD = 1008
  /// Full permute of two tables of SP elements overwriting one source table.
  | VPERMT2PS = 1009
  /// Full permute of two tables of qword elements overwriting one source table.
  | VPERMT2Q = 1010
  /// Permute packed word elements.
  | VPERMW = 1011
  /// Load Sparse Packed Doubleword Integer Values from Dense Memory / Register.
  | VPEXPANDD = 1012
  /// Load Sparse Packed Quadword Integer Values from Dense Memory / Register.
  | VPEXPANDQ = 1013
  /// Extract Byte.
  | VPEXTRB = 1014
  /// Extract DWord.
  | VPEXTRD = 1015
  /// Extract Word.
  | VPEXTRW = 1016
  /// Gather packed dword values using signed Dword/Qword indices.
  | VPGATHERDD = 1017
  /// Packed Horizontal Add (32-bit).
  | VPHADDD = 1018
  /// Packed Horizontal Add and Saturate (16-bit).
  | VPHADDSW = 1019
  /// Packed Horizontal Add (16-bit).
  | VPHADDW = 1020
  /// Packed Horizontal Word Minimum.
  | VPHMINPOSUW = 1021
  /// Packed Horizontal Subtract (32-bit).
  | VPHSUBD = 1022
  /// Packed Horizontal Subtract and Saturate (16-bit).
  | VPHSUBSW = 1023
  /// Packed Horizontal Subtract (16-bit).
  | VPHSUBW = 1024
  /// Insert Byte.
  | VPINSRB = 1025
  /// Insert Dword.
  | VPINSRD = 1026
  /// Insert Qword.
  | VPINSRQ = 1027
  /// Insert Word.
  | VPINSRW = 1028
  /// Count the number of leading zero bits of packed dword elements.
  | VPLZCNTD = 1029
  /// Count the number of leading zero bits of packed qword elements.
  | VPLZCNTQ = 1030
  /// Multiply and Add Packed Integers.
  | VPMADDWD = 1031
  /// Conditional SIMD Integer Packed Loads and Stores.
  | VPMASKMOVD = 1032
  /// Conditional SIMD Integer Packed Loads and Stores.
  | VPMASKMOVQ = 1033
  /// Maximum of Packed Signed Integers (byte).
  | VPMAXSB = 1034
  /// Maximum of Packed Signed Integers (dword).
  | VPMAXSD = 1035
  /// Compute maximum of packed signed 64-bit integer elements.
  | VPMAXSQ = 1036
  /// Maximum of Packed Signed Word Integers.
  | VPMAXSW = 1037
  /// Maximum of Packed Unsigned Byte Integers.
  | VPMAXUB = 1038
  /// Maximum of Packed Unsigned Integers (dword).
  | VPMAXUD = 1039
  /// Compute maximum of packed unsigned 64-bit integer elements.
  | VPMAXUQ = 1040
  /// Maximum of Packed Unsigned Integers (word).
  | VPMAXUW = 1041
  /// Minimum of Packed Signed Integers (byte).
  | VPMINSB = 1042
  /// Minimum of Packed Signed Integers (dword).
  | VPMINSD = 1043
  /// Compute minimum of packed signed 64-bit integer elements.
  | VPMINSQ = 1044
  /// Minimum of Packed Signed Word Integers.
  | VPMINSW = 1045
  /// Minimum of Packed Unsigned Byte Integers.
  | VPMINUB = 1046
  /// Minimum of Packed Dword Integers.
  | VPMINUD = 1047
  /// Compute minimum of packed unsigned 64-bit integer elements.
  | VPMINUQ = 1048
  /// Minimum of Packed Unsigned Integers (word).
  | VPMINUW = 1049
  /// Convert a vector register in 32/64-bit granularity to an opmask register.
  | VPMOVB2D = 1050
  /// Convert a Vector Register to a Mask.
  | VPMOVB2M = 1051
  /// Down Convert DWord to Byte.
  | VPMOVDB = 1052
  /// Down Convert DWord to Word.
  | VPMOVDW = 1053
  /// Convert opmask register to vector register in 8-bit granularity.
  | VPMOVM2B = 1054
  /// Convert opmask register to vector register in 32-bit granularity.
  | VPMOVM2D = 1055
  /// Convert opmask register to vector register in 64-bit granularity.
  | VPMOVM2Q = 1056
  /// Convert opmask register to vector register in 16-bit granularity.
  | VPMOVM2W = 1057
  /// Move Byte Mask.
  | VPMOVMSKB = 1058
  /// Convert a Vector Register to a Mask.
  | VPMOVQ2M = 1059
  /// Down Convert QWord to Byte.
  | VPMOVQB = 1060
  /// Down Convert QWord to DWord.
  | VPMOVQD = 1061
  /// Down Convert QWord to Word.
  | VPMOVQW = 1062
  /// Down Convert DWord to Byte.
  | VPMOVSDB = 1063
  /// Down Convert DWord to Word.
  | VPMOVSDW = 1064
  /// Down Convert QWord to Byte.
  | VPMOVSQB = 1065
  /// Down Convert QWord to Dword.
  | VPMOVSQD = 1066
  /// Down Convert QWord to Word.
  | VPMOVSQW = 1067
  /// Down Convert Word to Byte.
  | VPMOVSWB = 1068
  /// Packed Move with Sign Extend (8-bit to 32-bit).
  | VPMOVSXBD = 1069
  /// Packed Move with Sign Extend (8-bit to 64-bit).
  | VPMOVSXBQ = 1070
  /// Packed Move with Sign Extend (8-bit to 16-bit).
  | VPMOVSXBW = 1071
  /// Packed Move with Sign Extend (32-bit to 64-bit).
  | VPMOVSXDQ = 1072
  /// Packed Move with Sign Extend (16-bit to 32-bit).
  | VPMOVSXWD = 1073
  /// Packed Move with Sign Extend (16-bit to 64-bit).
  | VPMOVSXWQ = 1074
  /// Down Convert DWord to Byte.
  | VPMOVUSDB = 1075
  /// Down Convert DWord to Word.
  | VPMOVUSDW = 1076
  /// Down Convert QWord to Byte.
  | VPMOVUSQB = 1077
  /// Down Convert QWord to DWord.
  | VPMOVUSQD = 1078
  /// Down Convert QWord to Word.
  | VPMOVUSQW = 1079
  /// Down Convert Word to Byte.
  | VPMOVUSWB = 1080
  /// Convert a vector register in 16-bit granularity to an opmask register.
  | VPMOVW2M = 1081
  /// Down convert word elements in a vector to byte elements using truncation.
  | VPMOVWB = 1082
  /// Packed Move with Zero Extend (8-bit to 32-bit).
  | VPMOVZXBD = 1083
  /// Packed Move with Zero Extend (8-bit to 64-bit).
  | VPMOVZXBQ = 1084
  /// Packed Move with Zero Extend (8-bit to 16-bit).
  | VPMOVZXBW = 1085
  /// Packed Move with Zero Extend (32-bit to 64-bit).
  | VPMOVZXDQ = 1086
  /// Packed Move with Zero Extend (16-bit to 32-bit).
  | VPMOVZXWD = 1087
  /// Packed Move with Zero Extend (16-bit to 64-bit).
  | VPMOVZXWQ = 1088
  /// Multiply Packed Doubleword Integers.
  | VPMULDQ = 1089
  /// Packed Multiply High with Round and Scale.
  | VPMULHRSW = 1090
  /// Multiply Packed Unsigned Integers and Store High Result.
  | VPMULHUW = 1091
  /// Multiply Packed Signed Integers and Store High Result.
  | VPMULHW = 1092
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLD = 1093
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLQ = 1094
  /// Multiply Packed Signed Integers and Store Low Result.
  | VPMULLW = 1095
  /// Multiply Packed Unsigned Doubleword Integers.
  | VPMULUDQ = 1096
  /// Bitwise Logical OR.
  | VPOR = 1097
  /// Rotate dword elem left by a constant shift count with conditional update.
  | VPROLD = 1098
  /// Rotate qword elem left by a constant shift count with conditional update.
  | VPROLQ = 1099
  /// Rotate dword element left by shift counts specified.
  | VPROLVD = 1100
  /// Rotate qword element left by shift counts specified.
  | VPROLVQ = 1101
  /// Rotate dword element right by a constant shift count.
  | VPRORD = 1102
  /// Rotate qword element right by a constant shift count.
  | VPRORQ = 1103
  /// Rotate dword element right by shift counts specified.
  | VPRORRD = 1104
  /// Rotate qword element right by shift counts specified.
  | VPRORRQ = 1105
  /// Compute Sum of Absolute Differences.
  | VPSADBW = 1106
  /// Scatter dword elements in a vector to memory using dword indices.
  | VPSCATTERDD = 1107
  /// Scatter qword elements in a vector to memory using dword indices.
  | VPSCATTERDQ = 1108
  /// Scatter dword elements in a vector to memory using qword indices.
  | VPSCATTERQD = 1109
  /// Scatter qword elements in a vector to memory using qword indices.
  | VPSCATTERQQ = 1110
  /// Packed Shuffle Bytes.
  | VPSHUFB = 1111
  /// Shuffle Packed Doublewords.
  | VPSHUFD = 1112
  /// Shuffle Packed High Words.
  | VPSHUFHW = 1113
  /// Shuffle Packed Low Words.
  | VPSHUFLW = 1114
  /// Packed SIGN (byte).
  | VPSIGNB = 1115
  /// Packed SIGN (doubleword).
  | VPSIGND = 1116
  /// Packed SIGN (word).
  | VPSIGNW = 1117
  /// Shift Packed Data Left Logical (doubleword).
  | VPSLLD = 1118
  /// Shift Double Quadword Left Logical.
  | VPSLLDQ = 1119
  /// Shift Packed Data Left Logical (quadword).
  | VPSLLQ = 1120
  /// Variable Bit Shift Left Logical.
  | VPSLLVD = 1121
  /// Variable Bit Shift Left Logical.
  | VPSLLVQ = 1122
  /// Variable Bit Shift Left Logical.
  | VPSLLVW = 1123
  /// Shift Packed Data Left Logical (word).
  | VPSLLW = 1124
  /// Shift Packed Data Right Arithmetic (doubleword).
  | VPSRAD = 1125
  /// Shift qwords right by a constant shift count and shifting in sign bits.
  | VPSRAQ = 1126
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVD = 1127
  /// Shift qwords right by shift counts in a vector and shifting in sign bits.
  | VPSRAVQ = 1128
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVW = 1129
  /// Shift Packed Data Right Arithmetic (word).
  | VPSRAW = 1130
  /// Shift Packed Data Right Logical (doubleword).
  | VPSRLD = 1131
  /// Shift Double Quadword Right Logical.
  | VPSRLDQ = 1132
  /// Shift Packed Data Right Logical (quadword).
  | VPSRLQ = 1133
  /// Variable Bit Shift Right Logical.
  | VPSRLVD = 1134
  /// Variable Bit Shift Right Logical.
  | VPSRLVQ = 1135
  /// Variable Bit Shift Right Logical.
  | VPSRLVW = 1136
  /// Shift Packed Data Right Logical (word).
  | VPSRLW = 1137
  /// Subtract Packed Integers (byte).
  | VPSUBB = 1138
  /// Subtract Packed Integers (doubleword).
  | VPSUBD = 1139
  /// Subtract Packed Integers (quadword).
  | VPSUBQ = 1140
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | VPSUBSB = 1141
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | VPSUBSW = 1142
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPSUBUSB = 1143
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | VPSUBUSW = 1144
  /// Subtract Packed Integers (word).
  | VPSUBW = 1145
  /// Perform bitwise ternary logic operation of three vectors.
  | VPTERLOGD = 1146
  /// Perform bitwise ternary logic operation of three vectors.
  | VPTERLOGQ = 1147
  /// Bitwise Ternary Logic.
  | VPTERNLOGD = 1148
  /// Logical Compare.
  | VPTEST = 1149
  /// Perform bitwise AND of byte elems of two vecs and write results to opmask.
  | VPTESTMB = 1150
  /// Perform bitwise AND of dword elems of 2-vecs and write results to opmask.
  | VPTESTMD = 1151
  /// Perform bitwise AND of qword elems of 2-vecs and write results to opmask.
  | VPTESTMQ = 1152
  /// Perform bitwise AND of word elems of two vecs and write results to opmask.
  | VPTESTMW = 1153
  /// Perform bitwise NAND of byte elems of 2-vecs and write results to opmask.
  | VPTESTNMB = 1154
  /// Perform bitwise NAND of dword elems of 2-vecs and write results to opmask.
  | VPTESTNMD = 1155
  /// Perform bitwise NAND of qword elems of 2-vecs and write results to opmask.
  | VPTESTNMQ = 1156
  /// Perform bitwise NAND of word elems of 2-vecs and write results to opmask.
  | VPTESTNMW = 1157
  /// Unpack High Data.
  | VPUNPCKHBW = 1158
  /// Unpack High Data.
  | VPUNPCKHDQ = 1159
  /// Unpack High Data.
  | VPUNPCKHQDQ = 1160
  /// Unpack High Data.
  | VPUNPCKHWD = 1161
  /// Unpack Low Data.
  | VPUNPCKLBW = 1162
  /// Unpack Low Data.
  | VPUNPCKLDQ = 1163
  /// Unpack Low Data.
  | VPUNPCKLQDQ = 1164
  /// Unpack Low Data.
  | VPUNPCKLWD = 1165
  /// Logical Exclusive OR.
  | VPXOR = 1166
  /// Bitwise XOR of packed doubleword integers.
  | VPXORD = 1167
  /// Bitwise XOR of packed quadword integers.
  | VPXORQ = 1168
  /// Range Restriction Calculation For Packed Pairs of Float64 Values.
  | VRANGEPD = 1169
  /// Range Restriction Calculation For Packed Pairs of Float32 Values.
  | VRANGEPS = 1170
  /// Range Restriction Calculation From a pair of Scalar Float64 Values.
  | VRANGESD = 1171
  /// Range Restriction Calculation From a Pair of Scalar Float32 Values.
  | VRANGESS = 1172
  /// Compute Approximate Reciprocals of Packed Float64 Values.
  | VRCP14PD = 1173
  /// Compute Approximate Reciprocals of Packed Float32 Values.
  | VRCP14PS = 1174
  /// Compute Approximate Reciprocal of Scalar Float64 Value.
  | VRCP14SD = 1175
  /// Compute Approximate Reciprocal of Scalar Float32 Value.
  | VRCP14SS = 1176
  /// Computes the reciprocal approximation of the float64 values.
  | VRCP28PD = 1177
  /// Computes the reciprocal approximation of the float32 values.
  | VRCP28PS = 1178
  /// Computes the reciprocal approximation of the low float64 value.
  | VRCP28SD = 1179
  /// Computes the reciprocal approximation of the low float32 value.
  | VRCP28SS = 1180
  /// Compute reciprocals of packed single-precision floating-point values.
  | VRCPPS = 1181
  /// Compute Reciprocal of Scalar Single-Precision Floating-Point Values.
  | VRCPSS = 1182
  /// Perform Reduction Transformation on Packed Float64 Values.
  | VREDUCEPD = 1183
  /// Perform Reduction Transformation on Packed Float32 Values.
  | VREDUCEPS = 1184
  /// Perform a Reduction Transformation on a Scalar Float64 Value.
  | VREDUCESD = 1185
  /// Perform a Reduction Transformation on a Scalar Float32 Value.
  | VREDUCESS = 1186
  /// Round Packed Float64 Values To Include A Given Number Of Fraction Bits.
  | VRNDSCALEPD = 1187
  /// Round Packed Float32 Values To Include A Given Number Of Fraction Bits.
  | VRNDSCALEPS = 1188
  /// Round Scalar Float64 Value To Include A Given Number Of Fraction Bits.
  | VRNDSCALESD = 1189
  /// Round Scalar Float32 Value To Include A Given Number Of Fraction Bits.
  | VRNDSCALESS = 1190
  /// Round Packed Double-Precision Values.
  | VROUNDPD = 1191
  /// Round Packed Single-Precision Values.
  | VROUNDPS = 1192
  /// Round Scalar Double-Precision Value.
  | VROUNDSD = 1193
  /// Round Scalar Single-Precision Value.
  | VROUNDSS = 1194
  /// Compute Approximate Reciprocals of Square Roots of Packed Float64 Values.
  | VRSQRT14PD = 1195
  /// Compute Approximate Reciprocals of Square Roots of Packed Float32 Values.
  | VRSQRT14PS = 1196
  /// Compute Approximate Reciprocal of Square Root of Scalar Float64 Value.
  | VRSQRT14SD = 1197
  /// Compute Approximate Reciprocal of Square Root of Scalar Float32 Value.
  | VRSQRT14SS = 1198
  /// Computes the reciprocal square root of the float64 values.
  | VRSQRT28PD = 1199
  /// Computes the reciprocal square root of the float32 values.
  | VRSQRT28PS = 1200
  /// Computes the reciprocal square root of the low float64 value.
  | VRSQRT28SD = 1201
  /// Computes the reciprocal square root of the low float32 value.
  | VRSQRT28SS = 1202
  /// Compute Reciprocals of Square Roots of Packed Single-Precision FP Values.
  | VRSQRTPS = 1203
  /// Compute Reciprocal of Square Root of Scalar Single-Precision FP Value.
  | VRSQRTSS = 1204
  /// Multiply packed DP FP elements of a vector by powers.
  | VSCALEPD = 1205
  /// Multiply packed SP FP elements of a vector by powers.
  | VSCALEPS = 1206
  /// Multiply the low DP FP element of a vector by powers.
  | VSCALESD = 1207
  /// Multiply the low SP FP element of a vector by powers.
  | VSCALESS = 1208
  /// Scatter SP/DP FP elements in a vector to memory using dword indices.
  | VSCATTERDD = 1209
  /// Scatter SP/DP FP elements in a vector to memory using dword indices.
  | VSCATTERDQ = 1210
  /// Scatter SP/DP FP elements in a vector to memory using qword indices.
  | VSCATTERQD = 1211
  /// Scatter SP/DP FP elements in a vector to memory using qword indices.
  | VSCATTERQQ = 1212
  /// Shuffle 128-bit lanes of a vector with 32 bit granular conditional update.
  | VSHUFF32X4 = 1213
  /// Shuffle 128-bit lanes of a vector with 64 bit granular conditional update.
  | VSHUFF64X2 = 1214
  /// Shuffle 128-bit lanes of a vector with 32 bit granular conditional update.
  | VSHUFI32X4 = 1215
  /// Shuffle 128-bit lanes of a vector with 64 bit granular conditional update.
  | VSHUFI64X2 = 1216
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | VSHUFPD = 1217
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | VSHUFPS = 1218
  /// Compute packed square roots of packed double-precision FP values.
  | VSQRTPD = 1219
  /// Compute square roots of packed single-precision floating-point values.
  | VSQRTPS = 1220
  /// Compute scalar square root of scalar double-precision FP values.
  | VSQRTSD = 1221
  /// Compute square root of scalar single-precision floating-point values.
  | VSQRTSS = 1222
  /// Subtract Packed Double-Precision Floating-Point Values.
  | VSUBPD = 1223
  /// Subtract Packed Single-Precision Floating-Point Values.
  | VSUBPS = 1224
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | VSUBSD = 1225
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | VSUBSS = 1226
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | VUCOMISD = 1227
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | VUCOMISS = 1228
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | VUNPCKHPD = 1229
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | VUNPCKHPS = 1230
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | VUNPCKLPD = 1231
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | VUNPCKLPS = 1232
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | VXORPD = 1233
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | VXORPS = 1234
  /// Zero Upper Bits of YMM Registers.
  | VZEROUPPER = 1235
  /// Wait.
  | WAIT = 1236
  /// Write Back and Invalidate Cache.
  | WBINVD = 1237
  /// Write FS Segment Base.
  | WRFSBASE = 1238
  /// Write GS Segment Base.
  | WRGSBASE = 1239
  /// Write to Model Specific Register.
  | WRMSR = 1240
  /// Write Data to User Page Key Register.
  | WRPKRU = 1241
  /// Write to a shadow stack.
  | WRSSD = 1242
  /// Write to a shadow stack.
  | WRSSQ = 1243
  /// Write to a user mode shadow stack.
  | WRUSSD = 1244
  /// Write to a user mode shadow stack.
  | WRUSSQ = 1245
  /// Transactional Abort.
  | XABORT = 1246
  /// Prefix hint to the beginning of an HLE transaction region.
  | XACQUIRE = 1247
  /// Exchange and Add.
  | XADD = 1248
  /// Transactional Begin.
  | XBEGIN = 1249
  /// Exchange Register/Memory with Register.
  | XCHG = 1250
  /// Transactional End.
  | XEND = 1251
  /// Value of Extended Control Register.
  | XGETBV = 1252
  /// Table lookup translation.
  | XLAT = 1253
  /// Table Look-up Translation.
  | XLATB = 1254
  /// Logical Exclusive OR.
  | XOR = 1255
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | XORPD = 1256
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | XORPS = 1257
  /// Prefix hint to the end of an HLE transaction region.
  | XRELEASE = 1258
  /// Restore Processor Extended States.
  | XRSTOR = 1259
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS = 1260
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS64 = 1261
  /// Save Processor Extended States.
  | XSAVE = 1262
  /// Save processor extended states with compaction to memory.
  | XSAVEC = 1263
  /// Save processor extended states with compaction to memory.
  | XSAVEC64 = 1264
  /// Save Processor Extended States Optimized.
  | XSAVEOPT = 1265
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES = 1266
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES64 = 1267
  /// Set Extended Control Register.
  | XSETBV = 1268
  /// Test If In Transactional Execution.
  | XTEST = 1269
  /// Invalid Opcode.
  | InvalOP = 1270

// vim: set tw=80 sts=2 sw=2:
