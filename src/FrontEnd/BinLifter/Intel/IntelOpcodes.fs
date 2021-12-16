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
  /// Call to Interrupt (Interrupt 3-trap to debugger).
  | INT3 = 262
  /// Call to Interrupt (InteInterrupt 4-if overflow flag is 1).
  | INTO = 263
  /// Invalidate Internal Caches.
  | INVD = 264
  /// Invalidate Translations Derived from EPT.
  | INVEPT = 265
  /// Invalidate TLB Entries.
  | INVLPG = 266
  /// Invalidate Process-Context Identifier.
  | INVPCID = 267
  /// Invalidate Translations Based on VPID.
  | INVVPID = 268
  /// Return from interrupt.
  | IRET = 269
  /// Interrupt return (32-bit operand size).
  | IRETD = 270
  /// Interrupt return (64-bit operand size).
  | IRETQ = 271
  /// Interrupt return (16-bit operand size).
  | IRETW = 272
  /// Jump if Condition Is Met (Jump near if not below, CF = 0).
  | JAE = 273
  | JNC = 273
  | JNB = 273
  /// Jump if Condition Is Met (Jump short if below, CF = 1).
  | JC = 274
  | JNAE = 274
  | JB = 274
  /// Jump if Condition Is Met (Jump short if CX register is 0).
  | JCXZ = 275
  /// Jump if Condition Is Met (Jump short if ECX register is 0).
  | JECXZ = 276
  /// Jump if Condition Is Met (Jump near if not less, SF = OF).
  | JGE = 277
  | JNL = 277
  /// Far jmp.
  | JMPFar = 278
  /// Near jmp.
  | JMPNear = 279
  /// Jump if Condition Is Met (Jump short if below or equal, CF = 1 or ZF).
  | JNA = 280
  | JBE = 280
  /// Jump if Condition Is Met (Jump short if above, CF = 0 and ZF = 0).
  | JNBE = 281
  | JA = 281
  /// Jump if Cond Is Met (Jump short if less or equal, ZF = 1 or SF <> OF).
  | JNG = 282
  | JLE = 282
  /// Jump if Condition Is Met (Jump short if less, SF <> OF).
  | JNGE = 283
  | JL = 283
  /// Jump if Condition Is Met (Jump short if greater, ZF = 0 and SF = OF).
  | JNLE = 284
  | JG = 284
  /// Jump if Condition Is Met (Jump near if not overflow, OF = 0).
  | JNO = 285
  /// Jump if Condition Is Met (Jump near if not sign, SF = 0).
  | JNS = 286
  /// Jump if Condition Is Met (Jump near if not zero, ZF = 0).
  | JNZ = 287
  | JNE = 287
  /// Jump if Condition Is Met (Jump near if overflow, OF = 1).
  | JO = 288
  /// Jump if Condition Is Met (Jump near if parity, PF = 1).
  | JP = 289
  | JPE = 289
  /// Jump if Condition Is Met (Jump near if not parity, PF = 0).
  | JPO = 290
  | JNP = 290
  /// Jump if Condition Is Met (Jump short if RCX register is 0).
  | JRCXZ = 291
  /// Jump if Condition Is Met (Jump short if sign, SF = 1).
  | JS = 292
  /// Jump if Condition Is Met (Jump short if zero, ZF = 1).
  | JZ = 293
  | JE = 293
  /// Add two 8-bit opmasks.
  | KADDB = 294
  /// Add two 32-bit opmasks.
  | KADDD = 295
  /// Add two 64-bit opmasks.
  | KADDQ = 296
  /// Add two 16-bit opmasks.
  | KADDW = 297
  /// Logical AND two 8-bit opmasks.
  | KANDB = 298
  /// Logical AND two 32-bit opmasks.
  | KANDD = 299
  /// Logical AND NOT two 8-bit opmasks.
  | KANDNB = 300
  /// Logical AND NOT two 32-bit opmasks.
  | KANDND = 301
  /// Logical AND NOT two 64-bit opmasks.
  | KANDNQ = 302
  /// Logical AND NOT two 16-bit opmasks.
  | KANDNW = 303
  /// Logical AND two 64-bit opmasks.
  | KANDQ = 304
  /// Logical AND two 16-bit opmasks.
  | KANDW = 305
  /// Move from or move to opmask register of 8-bit data.
  | KMOVB = 306
  /// Move from or move to opmask register of 32-bit data.
  | KMOVD = 307
  /// Move from or move to opmask register of 64-bit data.
  | KMOVQ = 308
  /// Move from or move to opmask register of 16-bit data.
  | KMOVW = 309
  /// Bitwise NOT of two 8-bit opmasks.
  | KNOTB = 310
  /// Bitwise NOT of two 32-bit opmasks.
  | KNOTD = 311
  /// Bitwise NOT of two 64-bit opmasks.
  | KNOTQ = 312
  /// Bitwise NOT of two 16-bit opmasks.
  | KNOTW = 313
  /// Logical OR two 8-bit opmasks.
  | KORB = 314
  /// Logical OR two 32-bit opmasks.
  | KORD = 315
  /// Logical OR two 64-bit opmasks.
  | KORQ = 316
  /// Update EFLAGS according to the result of bitwise OR of two 8-bit opmasks.
  | KORTESTB = 317
  /// Update EFLAGS according to the result of bitwise OR of two 32-bit opmasks.
  | KORTESTD = 318
  /// Update EFLAGS according to the result of bitwise OR of two 64-bit opmasks.
  | KORTESTQ = 319
  /// Update EFLAGS according to the result of bitwise OR of two 16-bit opmasks.
  | KORTESTW = 320
  /// Logical OR two 16-bit opmasks.
  | KORW = 321
  /// Shift left 8-bitopmask by specified count.
  | KSHIFTLB = 322
  /// Shift left 32-bitopmask by specified count.
  | KSHIFTLD = 323
  /// Shift left 64-bitopmask by specified count.
  | KSHIFTLQ = 324
  /// Shift left 16-bitopmask by specified count.
  | KSHIFTLW = 325
  /// Shift right 8-bit opmask by specified count.
  | KSHIFTRB = 326
  /// Shift right 32-bit opmask by specified count.
  | KSHIFTRD = 327
  /// Shift right 64-bit opmask by specified count.
  | KSHIFTRQ = 328
  /// Shift right 16-bit opmask by specified count.
  | KSHIFTRW = 329
  /// Update EFLAGS according to result of bitwise TEST of two 8-bit opmasks.
  | KTESTB = 330
  /// Update EFLAGS according to result of bitwise TEST of two 32-bit opmasks.
  | KTESTD = 331
  /// Update EFLAGS according to result of bitwise TEST of two 64-bit opmasks.
  | KTESTQ = 332
  /// Update EFLAGS according to result of bitwise TEST of two 16-bit opmasks.
  | KTESTW = 333
  /// Unpack and interleave two 8-bit opmasks into 16-bit mask.
  | KUNPCKBW = 334
  /// Unpack and interleave two 32-bit opmasks into 64-bit mask.
  | KUNPCKDQ = 335
  /// Unpack and interleave two 16-bit opmasks into 32-bit mask.
  | KUNPCKWD = 336
  /// Bitwise logical XNOR of two 8-bit opmasks.
  | KXNORB = 337
  /// Bitwise logical XNOR of two 32-bit opmasks.
  | KXNORD = 338
  /// Bitwise logical XNOR of two 64-bit opmasks.
  | KXNORQ = 339
  /// Bitwise logical XNOR of two 16-bit opmasks.
  | KXNORW = 340
  /// Logical XOR of two 8-bit opmasks.
  | KXORB = 341
  /// Logical XOR of two 32-bit opmasks.
  | KXORD = 342
  /// Logical XOR of two 64-bit opmasks.
  | KXORQ = 343
  /// Logical XOR of two 16-bit opmasks.
  | KXORW = 344
  /// Load Status Flags into AH Register.
  | LAHF = 345
  /// Load Access Rights Byte.
  | LAR = 346
  /// Load Unaligned Integer 128 Bits.
  | LDDQU = 347
  /// Load MXCSR Register.
  | LDMXCSR = 348
  /// Load Far Pointer (DS).
  | LDS = 349
  /// Load Effective Address.
  | LEA = 350
  /// High Level Procedure Exit.
  | LEAVE = 351
  /// Load Far Pointer (ES).
  | LES = 352
  /// Load Fence.
  | LFENCE = 353
  /// Load Far Pointer (FS).
  | LFS = 354
  /// Load GlobalDescriptor Table Register.
  | LGDT = 355
  /// Load Far Pointer (GS).
  | LGS = 356
  /// Load Interrupt Descriptor Table Register.
  | LIDT = 357
  /// Load Local Descriptor Table Register.
  | LLDT = 358
  /// Load Machine Status Word.
  | LMSW = 359
  /// Assert LOCK# Signal Prefix.
  | LOCK = 360
  /// Load String (byte).
  | LODSB = 361
  /// Load String (doubleword).
  | LODSD = 362
  /// Load String (quadword).
  | LODSQ = 363
  /// Load String (word).
  | LODSW = 364
  /// Loop According to ECX Counter (count <> 0).
  | LOOP = 365
  /// Loop According to ECX Counter (count <> 0 and ZF = 1).
  | LOOPE = 366
  /// Loop According to ECX Counter (count <> 0 and ZF = 0).
  | LOOPNE = 367
  /// Load Segment Limit.
  | LSL = 368
  /// Load Far Pointer (SS).
  | LSS = 369
  /// Load Task Register.
  | LTR = 370
  /// the Number of Leading Zero Bits.
  | LZCNT = 371
  /// Store Selected Bytes of Double Quadword.
  | MASKMOVDQU = 372
  /// Store Selected Bytes of Quadword.
  | MASKMOVQ = 373
  /// Return Maximum Packed Double-Precision Floating-Point Values.
  | MAXPD = 374
  /// Return Maximum Packed Single-Precision Floating-Point Values.
  | MAXPS = 375
  /// Return Maximum Scalar Double-Precision Floating-Point Values.
  | MAXSD = 376
  /// Return Maximum Scalar Single-Precision Floating-Point Values.
  | MAXSS = 377
  /// Memory Fence.
  | MFENCE = 378
  /// Return Minimum Packed Double-Precision Floating-Point Values.
  | MINPD = 379
  /// Return Minimum Packed Single-Precision Floating-Point Values.
  | MINPS = 380
  /// Return Minimum Scalar Double-Precision Floating-Point Values.
  | MINSD = 381
  /// Return Minimum Scalar Single-Precision Floating-Point Values.
  | MINSS = 382
  /// Set Up Monitor Address.
  | MONITOR = 383
  /// MOV.
  | MOV = 384
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | MOVAPD = 385
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | MOVAPS = 386
  /// Move Data After Swapping Bytes.
  | MOVBE = 387
  /// Move Doubleword.
  | MOVD = 388
  /// Move One Double-FP and Duplicate.
  | MOVDDUP = 389
  /// Move Quadword from XMM to MMX Technology Register.
  | MOVDQ2Q = 390
  /// Move Aligned Double Quadword.
  | MOVDQA = 391
  /// Move Unaligned Double Quadword.
  | MOVDQU = 392
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | MOVHLPS = 393
  /// Move High Packed Double-Precision Floating-Point Value.
  | MOVHPD = 394
  /// Move High Packed Single-Precision Floating-Point Values.
  | MOVHPS = 395
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | MOVLHPS = 396
  /// Move Low Packed Double-Precision Floating-Point Value.
  | MOVLPD = 397
  /// Move Low Packed Single-Precision Floating-Point Values.
  | MOVLPS = 398
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | MOVMSKPD = 399
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | MOVMSKPS = 400
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQ = 401
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQA = 402
  /// Store Doubleword Using Non-Temporal Hint.
  | MOVNTI = 403
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPD = 404
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPS = 405
  /// Store of Quadword Using Non-Temporal Hint.
  | MOVNTQ = 406
  /// Move Quadword.
  | MOVQ = 407
  /// Move Quadword from MMX Technology to XMM Register.
  | MOVQ2DQ = 408
  /// Move Data from String to String (byte).
  | MOVSB = 409
  /// Move Data from String to String (doubleword).
  | MOVSD = 410
  /// Move Packed Single-FP High and Duplicate.
  | MOVSHDUP = 411
  /// Move Packed Single-FP Low and Duplicate.
  | MOVSLDUP = 412
  /// Move Data from String to String (quadword).
  | MOVSQ = 413
  /// Move Scalar Single-Precision Floating-Point Values.
  | MOVSS = 414
  /// Move Data from String to String (word).
  | MOVSW = 415
  /// Move with Sign-Extension.
  | MOVSX = 416
  /// Move with Sign-Extension (doubleword to quadword).
  | MOVSXD = 417
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | MOVUPD = 418
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | MOVUPS = 419
  /// Move with Zero-Extend.
  | MOVZX = 420
  /// Compute Multiple Packed Sums of Absolute Difference.
  | MPSADBW = 421
  /// Unsigned Multiply.
  | MUL = 422
  /// Multiply Packed Double-Precision Floating-Point Values.
  | MULPD = 423
  /// Multiply Packed Single-Precision Floating-Point Values.
  | MULPS = 424
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | MULSD = 425
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | MULSS = 426
  /// Unsigned multiply without affecting arithmetic flags.
  | MULX = 427
  /// Monitor Wait.
  | MWAIT = 428
  /// Two's Complement Negation.
  | NEG = 429
  /// No Operation.
  | NOP = 430
  /// One's Complement Negation.
  | NOT = 431
  /// Logical Inclusive OR.
  | OR = 432
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | ORPD = 433
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | ORPS = 434
  /// Output to Port.
  | OUT = 435
  /// Output String to Port.
  | OUTS = 436
  /// Output String to Port (byte).
  | OUTSB = 437
  /// Output String to Port (doubleword).
  | OUTSD = 438
  /// Output String to Port (word).
  | OUTSW = 439
  /// Computes the absolute value of each signed byte data element.
  | PABSB = 440
  /// Computes the absolute value of each signed 32-bit data element.
  | PABSD = 441
  /// Computes the absolute value of each signed 16-bit data element.
  | PABSW = 442
  /// Pack with Signed Saturation.
  | PACKSSDW = 443
  /// Pack with Signed Saturation.
  | PACKSSWB = 444
  /// Pack with Unsigned Saturation.
  | PACKUSDW = 445
  /// Pack with Unsigned Saturation.
  | PACKUSWB = 446
  /// Add Packed byte Integers.
  | PADDB = 447
  /// Add Packed Doubleword Integers.
  | PADDD = 448
  /// Add Packed Quadword Integers.
  | PADDQ = 449
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | PADDSB = 450
  /// Add Packed Signed Integers with Signed Saturation (word).
  | PADDSW = 451
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | PADDUSB = 452
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | PADDUSW = 453
  /// Add Packed word Integers.
  | PADDW = 454
  /// Packed Align Right.
  | PALIGNR = 455
  /// Logical AND.
  | PAND = 456
  /// Logical AND NOT.
  | PANDN = 457
  /// Spin Loop Hint.
  | PAUSE = 458
  /// Average Packed Integers (byte).
  | PAVGB = 459
  /// Average Packed Integers (word).
  | PAVGW = 460
  /// Variable Blend Packed Bytes.
  | PBLENDVB = 461
  /// Blend Packed Words.
  | PBLENDW = 462
  /// Perform carryless multiplication of two 64-bit numbers.
  | PCLMULQDQ = 463
  /// Compare Packed Data for Equal (byte).
  | PCMPEQB = 464
  /// Compare Packed Data for Equal (doubleword).
  | PCMPEQD = 465
  /// Compare Packed Data for Equal (quadword).
  | PCMPEQQ = 466
  /// Compare packed words for equal.
  | PCMPEQW = 467
  /// Packed Compare Explicit Length Strings, Return Index.
  | PCMPESTRI = 468
  /// Packed Compare Explicit Length Strings, Return Mask.
  | PCMPESTRM = 469
  /// Compare Packed Signed Integers for Greater Than (byte).
  | PCMPGTB = 470
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | PCMPGTD = 471
  /// Performs logical compare of greater-than on packed integer quadwords.
  | PCMPGTQ = 472
  /// Compare Packed Signed Integers for Greater Than (word).
  | PCMPGTW = 473
  /// Packed Compare Implicit Length Strings, Return Index.
  | PCMPISTRI = 474
  /// Packed Compare Implicit Length Strings, Return Mask.
  | PCMPISTRM = 475
  /// Parallel deposit of bits using a mask.
  | PDEP = 476
  /// Parallel extraction of bits using a mask.
  | PEXT = 477
  /// Extract Byte.
  | PEXTRB = 478
  /// Extract Dword.
  | PEXTRD = 479
  /// Extract Qword.
  | PEXTRQ = 480
  /// Extract Word.
  | PEXTRW = 481
  /// Packed Horizontal Add.
  | PHADDD = 482
  /// Packed Horizontal Add and Saturate.
  | PHADDSW = 483
  /// Packed Horizontal Add.
  | PHADDW = 484
  /// Packed Horizontal Word Minimum.
  | PHMINPOSUW = 485
  /// Packed Horizontal Subtract.
  | PHSUBD = 486
  /// Packed Horizontal Subtract and Saturate.
  | PHSUBSW = 487
  /// Packed Horizontal Subtract.
  | PHSUBW = 488
  /// Insert Byte.
  | PINSRB = 489
  /// Insert a dword value from 32-bit register or memory into an XMM register.
  | PINSRD = 490
  /// Insert a qword value from 64-bit register or memory into an XMM register.
  | PINSRQ = 491
  /// Insert Word.
  | PINSRW = 492
  /// Multiply and Add Packed Signed and Unsigned Bytes.
  | PMADDUBSW = 493
  /// Multiply and Add Packed Integers.
  | PMADDWD = 494
  /// Compare packed signed byte integers.
  | PMAXSB = 495
  /// Compare packed signed dword integers.
  | PMAXSD = 496
  /// Maximum of Packed Signed Word Integers.
  | PMAXSW = 497
  /// Maximum of Packed Unsigned Byte Integers.
  | PMAXUB = 498
  /// Compare packed unsigned dword integers.
  | PMAXUD = 499
  /// Compare packed unsigned word integers.
  | PMAXUW = 500
  /// Minimum of Packed Signed Byte Integers.
  | PMINSB = 501
  /// Compare packed signed dword integers.
  | PMINSD = 502
  /// Minimum of Packed Signed Word Integers.
  | PMINSW = 503
  /// Minimum of Packed Unsigned Byte Integers.
  | PMINUB = 504
  /// Minimum of Packed Dword Integers.
  | PMINUD = 505
  /// Compare packed unsigned word integers.
  | PMINUW = 506
  /// Move Byte Mask.
  | PMOVMSKB = 507
  /// Packed Move with Sign Extend.
  | PMOVSXBD = 508
  /// Packed Move with Sign Extend.
  | PMOVSXBQ = 509
  /// Packed Move with Sign Extend.
  | PMOVSXBW = 510
  /// Packed Move with Sign Extend.
  | PMOVSXDQ = 511
  /// Packed Move with Sign Extend.
  | PMOVSXWD = 512
  /// Packed Move with Sign Extend.
  | PMOVSXWQ = 513
  /// Packed Move with Zero Extend.
  | PMOVZXBD = 514
  /// Packed Move with Zero Extend.
  | PMOVZXBQ = 515
  /// Packed Move with Zero Extend.
  | PMOVZXBW = 516
  /// Packed Move with Zero Extend.
  | PMOVZXDQ = 517
  /// Packed Move with Zero Extend.
  | PMOVZXWD = 518
  /// Packed Move with Zero Extend.
  | PMOVZXWQ = 519
  /// Multiply Packed Doubleword Integers.
  | PMULDQ = 520
  /// Packed Multiply High with Round and Scale.
  | PMULHRSW = 521
  /// Multiply Packed Unsigned Integers and Store High Result.
  | PMULHUW = 522
  /// Multiply Packed Signed Integers and Store High Result.
  | PMULHW = 523
  /// Multiply Packed Integers and Store Low Result.
  | PMULLD = 524
  /// Multiply Packed Signed Integers and Store Low Result.
  | PMULLW = 525
  /// Multiply Packed Unsigned Doubleword Integers.
  | PMULUDQ = 526
  /// Pop a Value from the Stack.
  | POP = 527
  /// Pop All General-Purpose Registers (word).
  | POPA = 528
  /// Pop All General-Purpose Registers (doubleword).
  | POPAD = 529
  /// Return the Count of Number of Bits Set to 1.
  | POPCNT = 530
  /// Pop Stack into EFLAGS Register (lower 16bits EFLAGS).
  | POPF = 531
  /// Pop Stack into EFLAGS Register (EFLAGS).
  | POPFD = 532
  /// Pop Stack into EFLAGS Register (RFLAGS).
  | POPFQ = 533
  /// Bitwise Logical OR.
  | POR = 534
  /// Prefetch Data Into Caches (using NTA hint).
  | PREFETCHNTA = 535
  /// Prefetch Data Into Caches (using T0 hint).
  | PREFETCHT0 = 536
  /// Prefetch Data Into Caches (using T1 hint).
  | PREFETCHT1 = 537
  /// Prefetch Data Into Caches (using T2 hint).
  | PREFETCHT2 = 538
  /// Prefetch Data into Caches in Anticipation of a Write.
  | PREFETCHW = 539
  /// Prefetch Vector Data Into Caches with Intent to Write and T1 Hint.
  | PREFETCHWT1 = 540
  /// Compute Sum of Absolute Differences.
  | PSADBW = 541
  /// Packed Shuffle Bytes.
  | PSHUFB = 542
  /// Shuffle Packed Doublewords.
  | PSHUFD = 543
  /// Shuffle Packed High Words.
  | PSHUFHW = 544
  /// Shuffle Packed Low Words.
  | PSHUFLW = 545
  /// Shuffle Packed Words.
  | PSHUFW = 546
  /// Packed Sign Byte.
  | PSIGNB = 547
  /// Packed Sign Doubleword.
  | PSIGND = 548
  /// Packed Sign Word.
  | PSIGNW = 549
  /// Shift Packed Data Left Logical (doubleword).
  | PSLLD = 550
  /// Shift Double Quadword Left Logical.
  | PSLLDQ = 551
  /// Shift Packed Data Left Logical (quadword).
  | PSLLQ = 552
  /// Shift Packed Data Left Logical (word).
  | PSLLW = 553
  /// Shift Packed Data Right Arithmetic (doubleword).
  | PSRAD = 554
  /// Shift Packed Data Right Arithmetic (word).
  | PSRAW = 555
  /// Shift Packed Data Right Logical (doubleword).
  | PSRLD = 556
  /// Shift Double Quadword Right Logical.
  | PSRLDQ = 557
  /// Shift Packed Data Right Logical (quadword).
  | PSRLQ = 558
  /// Shift Packed Data Right Logical (word).
  | PSRLW = 559
  /// Subtract Packed Integers (byte).
  | PSUBB = 560
  /// Subtract Packed Integers (doubleword).
  | PSUBD = 561
  /// Subtract Packed Integers (quadword).
  | PSUBQ = 562
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | PSUBSB = 563
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | PSUBSW = 564
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | PSUBUSB = 565
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | PSUBUSW = 566
  /// Subtract Packed Integers (word).
  | PSUBW = 567
  /// Logical Compare.
  | PTEST = 568
  /// Unpack High Data.
  | PUNPCKHBW = 569
  /// Unpack High Data.
  | PUNPCKHDQ = 570
  /// Unpack High Data.
  | PUNPCKHQDQ = 571
  /// Unpack High Data.
  | PUNPCKHWD = 572
  /// Unpack Low Data.
  | PUNPCKLBW = 573
  /// Unpack Low Data.
  | PUNPCKLDQ = 574
  /// Unpack Low Data.
  | PUNPCKLQDQ = 575
  /// Unpack Low Data.
  | PUNPCKLWD = 576
  /// Push Word, Doubleword or Quadword Onto the Stack.
  | PUSH = 577
  /// Push All General-Purpose Registers (word).
  | PUSHA = 578
  /// Push All General-Purpose Registers (doubleword).
  | PUSHAD = 579
  /// Push EFLAGS Register onto the Stack (16bits of EFLAGS).
  | PUSHF = 580
  /// Push EFLAGS Register onto the Stack (EFLAGS).
  | PUSHFD = 581
  /// Push EFLAGS Register onto the Stack (RFLAGS).
  | PUSHFQ = 582
  /// Logical Exclusive OR.
  | PXOR = 583
  /// Rotate x bits (CF, r/m(x)) left once.
  | RCL = 584
  /// Compute reciprocals of packed single-precision floating-point values.
  | RCPPS = 585
  /// Compute reciprocal of scalar single-precision floating-point values.
  | RCPSS = 586
  /// Rotate x bits (CF, r/m(x)) right once.
  | RCR = 587
  /// Read FS Segment Base.
  | RDFSBASE = 588
  /// Read GS Segment Base.
  | RDGSBASE = 589
  /// Read from Model Specific Register.
  | RDMSR = 590
  /// Read Protection Key Rights for User Pages.
  | RDPKRU = 591
  /// Read Performance-Monitoring Counters.
  | RDPMC = 592
  /// Read Random Number.
  | RDRAND = 593
  /// Read Random SEED.
  | RDSEED = 594
  /// Read shadow stack point (SSP).
  | RDSSPD = 595
  /// Read shadow stack point (SSP).
  | RDSSPQ = 596
  /// Read Time-Stamp Counter.
  | RDTSC = 597
  /// Read Time-Stamp Counter and Processor ID.
  | RDTSCP = 598
  /// Repeat while ECX not zero.
  | REP = 599
  /// Repeat while equal/Repeat while zero.
  | REPE = 600
  /// Repeat while not equal/Repeat while not zero.
  | REPNE = 601
  /// Repeat while not equal/Repeat while not zero.
  | REPNZ = 602
  /// Repeat while equal/Repeat while zero.
  | REPZ = 603
  /// Far return.
  | RETFar = 604
  /// Far return w/ immediate.
  | RETFarImm = 605
  /// Near return.
  | RETNear = 606
  /// Near return w/ immediate .
  | RETNearImm = 607
  /// Rotate x bits r/m(x) left once.
  | ROL = 608
  /// Rotate x bits r/m(x) right once.
  | ROR = 609
  /// Rotate right without affecting arithmetic flags.
  | RORX = 610
  /// Round Packed Double Precision Floating-Point Values.
  | ROUNDPD = 611
  /// Round Packed Single Precision Floating-Point Values.
  | ROUNDPS = 612
  /// Round Scalar Double Precision Floating-Point Values.
  | ROUNDSD = 613
  /// Round Scalar Single Precision Floating-Point Values.
  | ROUNDSS = 614
  /// Resume from System Management Mode.
  | RSM = 615
  /// Compute reciprocals of square roots of packed single-precision FP values.
  | RSQRTPS = 616
  /// Compute reciprocal of square root of scalar single-precision FP values.
  | RSQRTSS = 617
  /// Restore a shadow stack pointer (SSP).
  | RSTORSSP = 618
  /// Store AH into Flags.
  | SAHF = 619
  /// Shift.
  | SAR = 620
  /// Shift arithmetic right.
  | SARX = 621
  /// Save previous shadow stack pointer (SSP).
  | SAVEPREVSSP = 622
  /// Integer Subtraction with Borrow.
  | SBB = 623
  /// Scan String (byte).
  | SCASB = 624
  /// Scan String (doubleword).
  | SCASD = 625
  /// Scan String (quadword).
  | SCASQ = 626
  /// Scan String (word).
  | SCASW = 627
  /// Set byte if above (CF = 0 and ZF = 0).
  | SETA = 628
  /// Set byte if below (CF = 1).
  | SETB = 629
  /// Set byte if below or equal (CF = 1 or ZF = 1).
  | SETBE = 630
  /// Set byte if greater (ZF = 0 and SF = OF).
  | SETG = 631
  /// Set byte if less (SF <> OF).
  | SETL = 632
  /// Set byte if less or equal (ZF = 1 or SF <> OF).
  | SETLE = 633
  /// Set byte if not below (CF = 0).
  | SETNB = 634
  /// Set byte if not less (SF = OF).
  | SETNL = 635
  /// Set byte if not overflow (OF = 0).
  | SETNO = 636
  /// Set byte if not parity (PF = 0).
  | SETNP = 637
  /// Set byte if not sign (SF = 0).
  | SETNS = 638
  /// Set byte if not zero (ZF = 0).
  | SETNZ = 639
  /// Set byte if overflow (OF = 1).
  | SETO = 640
  /// Set byte if parity (PF = 1).
  | SETP = 641
  /// Set byte if sign (SF = 1).
  | SETS = 642
  /// Set busy bit in a supervisor shadow stack token.
  | SETSSBSY = 643
  /// Set byte if sign (ZF = 1).
  | SETZ = 644
  /// Store Fence.
  | SFENCE = 645
  /// Store Global Descriptor Table Register.
  | SGDT = 646
  /// Perform an Intermediate Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG1 = 647
  /// Perform a Final Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG2 = 648
  /// Calculate SHA1 state E after four rounds.
  | SHA1NEXTE = 649
  /// Perform four rounds of SHA1 operations.
  | SHA1RNDS4 = 650
  /// Perform an intermediate calculation for the next 4 SHA256 message dwords.
  | SHA256MSG1 = 651
  /// Perform the final calculation for the next four SHA256 message dwords.
  | SHA256MSG2 = 652
  /// Perform two rounds of SHA256 operations.
  | SHA256RNDS2 = 653
  /// Shift.
  | SHL = 654
  /// Double Precision Shift Left.
  | SHLD = 655
  /// Shift logic left.
  | SHLX = 656
  /// Shift.
  | SHR = 657
  /// Double Precision Shift Right.
  | SHRD = 658
  /// Shift logic right.
  | SHRX = 659
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | SHUFPD = 660
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | SHUFPS = 661
  /// Store Interrupt Descriptor Table Register.
  | SIDT = 662
  /// Store Local Descriptor Table Register.
  | SLDT = 663
  /// Store Machine Status Word.
  | SMSW = 664
  /// Compute packed square roots of packed double-precision FP values.
  | SQRTPD = 665
  /// Compute square roots of packed single-precision floating-point values.
  | SQRTPS = 666
  /// Compute scalar square root of scalar double-precision FP values.
  | SQRTSD = 667
  /// Compute square root of scalar single-precision floating-point values.
  | SQRTSS = 668
  /// Set AC Flag in EFLAGS Register.
  | STAC = 669
  /// Set Carry Flag.
  | STC = 670
  /// Set Direction Flag.
  | STD = 671
  /// Set Interrupt Flag.
  | STI = 672
  /// Store MXCSR Register State.
  | STMXCSR = 673
  /// Store String (store AL).
  | STOSB = 674
  /// Store String (store EAX).
  | STOSD = 675
  /// Store String (store RAX).
  | STOSQ = 676
  /// Store String (store AX).
  | STOSW = 677
  /// Store Task Register.
  | STR = 678
  /// Subtract.
  | SUB = 679
  /// Subtract Packed Double-Precision Floating-Point Values.
  | SUBPD = 680
  /// Subtract Packed Single-Precision Floating-Point Values.
  | SUBPS = 681
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | SUBSD = 682
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | SUBSS = 683
  /// Swap GS Base Register.
  | SWAPGS = 684
  /// Fast System Call.
  | SYSCALL = 685
  /// Fast System Call.
  | SYSENTER = 686
  /// Fast Return from Fast System Call.
  | SYSEXIT = 687
  /// Return From Fast System Call.
  | SYSRET = 688
  /// Logical Compare.
  | TEST = 689
  /// Count the Number of Trailing Zero Bits.
  | TZCNT = 690
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | UCOMISD = 691
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | UCOMISS = 692
  /// Undefined instruction.
  | UD = 693
  /// Undefined Instruction (Raise invalid opcode exception).
  | UD2 = 694
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | UNPCKHPD = 695
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | UNPCKHPS = 696
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | UNPCKLPD = 697
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | UNPCKLPS = 698
  /// Packed Single-Precision Floating-Point Fused Multiply-Add.
  | V4FMADDPS = 699
  /// Scalar Single-Precision Floating-Point Fused Multiply-Add.
  | V4FMADDSS = 700
  /// Packed Single-Precision Floating-Point Fused Multiply-Add and Negate.
  | V4FNMADDPS = 701
  /// Scalar Single-Precision Floating-Point Fused Multiply-Add and Negate.
  | V4FNMADDSS = 702
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPD = 703
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPS = 704
  /// Add Scalar Double-Precision Floating-Point Values.
  | VADDSD = 705
  /// Add Scalar Single-Precision Floating-Point Values.
  | VADDSS = 706
  /// Packed Double-FP Add/Subtract.
  | VADDSUBPD = 707
  /// Packed Single-FP Add/Subtract.
  | VADDSUBPS = 708
  /// Perform One Round of an AES Decryption Flow.
  | VAESDEC = 709
  /// Perform Last Round of an AES Decryption Flow.
  | VAESDECLAST = 710
  /// Perform One Round of an AES Encryption Flow.
  | VAESENC = 711
  /// Perform Last Round of an AES Encryption Flow.
  | VAESENCLAST = 712
  /// Perform dword alignment of two concatenated source vectors.
  | VALIGND = 713
  /// Perform qword alignment of two concatenated source vectors.
  | VALIGNQ = 714
  /// Bitwise Logical AND of Packed Double-Precision Floating-Point Values.
  | VANDNPD = 715
  /// Bitwise Logical AND of Packed Single-Precision Floating-Point Values.
  | VANDNPS = 716
  /// Bitwise Logical AND NOT of Packed Double-Precision Floating-Point Values.
  | VANDPD = 717
  /// Bitwise Logical AND NOT of Packed Single-Precision Floating-Point Values.
  | VANDPS = 718
  /// Replace the VBLENDVPD instructions (using opmask as select control).
  | VBLENDMPD = 719
  /// Replace the VBLENDVPS instructions (using opmask as select control).
  | VBLENDMPS = 720
  /// Blend Packed Double-Precision Floats.
  | VBLENDPD = 721
  /// Blend Packed Single-Precision Floats.
  | VBLENDPS = 722
  /// Variable Blend Packed Double-Precision Floats.
  | VBLENDVPD = 723
  /// Variable Blend Packed Single-Precision Floats.
  | VBLENDVPS = 724
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTF128 = 725
  /// Broadcast 128 bits of int data in mem to low and high 128-bits in ymm1.
  | VBROADCASTI128 = 726
  /// Broadcast two dword elements.
  | VBROADCASTI32X2 = 727
  /// Broadcast four dword elements.
  | VBROADCASTI32X4 = 728
  /// Broadcast eight dword elements.
  | VBROADCASTI32X8 = 729
  /// Broadcast two qword elements.
  | VBROADCASTI64X2 = 730
  /// Broadcast four qword elements.
  | VBROADCASTI64X4 = 731
  /// Broadcast low double-precision floating-point element.
  | VBROADCASTSD = 732
  /// Broadcast Floating-Point Data.
  | VBROADCASTSS = 733
  /// Compare Packed Double-Precision Floating-Point Values.
  | VCMPPD = 734
  /// Compare Packed Single-Precision Floating-Point Values.
  | VCMPPS = 735
  /// Compare Scalar Double-Precision Floating-Point Values.
  | VCMPSD = 736
  /// Scalar Single-Precision Floating-Point Values.
  | VCMPSS = 737
  /// Compare Scalar Ordered Double-Precision FP Values and Set EFLAGS.
  | VCOMISD = 738
  /// Compare Scalar Ordered Single-Precision FP Values and Set EFLAGS.
  | VCOMISS = 739
  /// Compress packed DP elements of a vector.
  | VCOMPRESSPD = 740
  /// Compress packed SP elements of a vector.
  | VCOMPRESSPS = 741
  /// Convert two packed signed doubleword integers.
  | VCVTDQ2PD = 742
  /// Convert Packed Dword Integers to Packed Single-Precision FP Values.
  | VCVTDQ2PS = 743
  /// Convert Two Packed Single Data to One Packed BF16 Data.
  | VCVTNE2PS2BF16 = 744
  /// Convert Packed Single Data to Packed BF16 Data.
  | VCVTNEPS2BF16 = 745
  /// Convert two packed double-precision floating-point values.
  | VCVTPD2PS = 746
  /// Convert Packed Double-Precision FP Values to Packed Quadword Integers.
  | VCVTPD2QQ = 747
  /// Convert Packed DP FP Values to Packed Unsigned DWord Integers.
  | VCVTPD2UDQ = 748
  /// Convert Packed DP FP Values to Packed Unsigned QWord Integers.
  | VCVTPD2UQQ = 749
  /// Convert 16-bit FP values to Single-Precision FP values.
  | VCVTPH2PS = 750
  /// Conv Packed Single-Precision FP Values to Packed Dbl-Precision FP Values.
  | VCVTPS2PD = 751
  /// Convert Single-Precision FP value to 16-bit FP value.
  | VCVTPS2PH = 752
  /// Convert Packed SP FP Values to Packed Signed QWord Int Values.
  | VCVTPS2QQ = 753
  /// Convert Packed SP FP Values to Packed Unsigned DWord Int Values.
  | VCVTPS2UDQ = 754
  /// Convert Packed SP FP Values to Packed Unsigned QWord Int Values.
  | VCVTPS2UQQ = 755
  /// Convert Packed Quadword Integers to Packed Double-Precision FP Values.
  | VCVTQQ2PD = 756
  /// Convert Packed Quadword Integers to Packed Single-Precision FP Values.
  | VCVTQQ2PS = 757
  /// Convert Scalar Double-Precision FP Value to Integer.
  | VCVTSD2SI = 758
  /// Convert Scalar Double-Precision FP Val to Scalar Single-Precision FP Val.
  | VCVTSD2SS = 759
  /// Convert Scalar Double-Precision FP Value to Unsigned Doubleword Integer.
  | VCVTSD2USI = 760
  /// Convert Dword Integer to Scalar Double-Precision FP Value.
  | VCVTSI2SD = 761
  /// Convert Dword Integer to Scalar Single-Precision FP Value.
  | VCVTSI2SS = 762
  /// Convert Scalar Single-Precision FP Val to Scalar Double-Precision FP Val.
  | VCVTSS2SD = 763
  /// Convert Scalar Single-Precision FP Value to Dword Integer.
  | VCVTSS2SI = 764
  /// Convert Scalar Single-Precision FP Value to Unsigned Doubleword Integer.
  | VCVTSS2USI = 765
  /// Conv with Trunc Packed Double-Precision FP Val to Packed Dword Integers.
  | VCVTTPD2DQ = 766
  /// Convert with Truncation Packed DP FP Values to Packed QWord Integers.
  | VCVTTPD2QQ = 767
  /// Convert with Truncation Packed DP FP Values to Packed Unsigned DWord Int.
  | VCVTTPD2UDQ = 768
  /// Convert with Truncation Packed DP FP Values to Packed Unsigned QWord Int.
  | VCVTTPD2UQQ = 769
  /// Conv with Trunc Packed Single-Precision FP Val to Packed Dword Integers.
  | VCVTTPS2DQ = 770
  /// Convert with Truncation Packed SP FP Values to Packed Signed QWord Int.
  | VCVTTPS2QQ = 771
  /// Convert with Truncation Packed SP FP Values to Packed Unsigned DWord Int.
  | VCVTTPS2UDQ = 772
  /// Convert with Truncation Packed SP FP Values to Packed Unsigned QWord Int.
  | VCVTTPS2UQQ = 773
  /// Convert with Truncation Scalar Double-Precision FP Value to Signed.
  | VCVTTSD2SI = 774
  /// Convert with Truncation Scalar DP FP Value to Unsigned Integer.
  | VCVTTSD2USI = 775
  /// Convert with Truncation Scalar Single-Precision FP Value to Dword Integer.
  | VCVTTSS2SI = 776
  /// Convert with Truncation Scalar Single-Precision FP Value to Unsigned Int.
  | VCVTTSS2USI = 777
  /// Convert Packed Unsigned DWord Integers to Packed DP FP Values.
  | VCVTUDQ2PD = 778
  /// Convert Packed Unsigned DWord Integers to Packed SP FP Values.
  | VCVTUDQ2PS = 779
  /// Convert Packed Unsigned QWord Integers to Packed DP FP Values.
  | VCVTUQQ2PD = 780
  /// Convert Packed Unsigned QWord Integers to Packed SP FP Values.
  | VCVTUQQ2PS = 781
  /// Convert an signed integer to the low DP FP elem and merge to a vector.
  | VCVTUSI2SD = 782
  /// Convert an signed integer to the low SP FP elem and merge to a vector.
  | VCVTUSI2SS = 783
  /// Convert an unsigned integer to the low DP FP elem and merge to a vector.
  | VCVTUSI2USD = 784
  /// Convert an unsigned integer to the low SP FP elem and merge to a vector.
  | VCVTUSI2USS = 785
  /// Double Block Packed Sum-Absolute-Differences (SAD) on Unsigned Bytes.
  | VDBPSADBW = 786
  /// Divide Packed Double-Precision Floating-Point Values.
  | VDIVPD = 787
  /// Divide Packed Single-Precision Floating-Point Values.
  | VDIVPS = 788
  /// Divide Scalar Double-Precision Floating-Point Values.
  | VDIVSD = 789
  /// Divide Scalar Single-Precision Floating-Point Values.
  | VDIVSS = 790
  /// Dot Product of BF16 Pairs Accumulated into Packed Single Precision.
  | VDPBF16PS = 791
  /// Verify a Segment for Reading.
  | VERR = 792
  /// Verify a Segment for Writing.
  | VERW = 793
  /// Compute approximate base-2 exponential of packed DP FP elems of a vector.
  | VEXP2PD = 794
  /// Compute approximate base-2 exponential of packed SP FP elems of a vector.
  | VEXP2PS = 795
  /// Compute approximate base-2 exponential of the low DP FP elem of a vector.
  | VEXP2SD = 796
  /// Compute approximate base-2 exponential of the low SP FP elem of a vector.
  | VEXP2SS = 797
  /// Load Sparse Packed Double-Precision FP Values from Dense Memory.
  | VEXPANDPD = 798
  /// Load Sparse Packed Single-Precision FP Values from Dense Memory.
  | VEXPANDPS = 799
  /// Extract Packed Floating-Point Values.
  | VEXTRACTF128 = 800
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTF32X4 = 801
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTF32X8 = 802
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTF64X2 = 803
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTF64X4 = 804
  /// Extract packed Integer Values.
  | VEXTRACTI128 = 805
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTI32X4 = 806
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTI32X8 = 807
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTI64X2 = 808
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTI64X4 = 809
  /// Extract From Packed Single-Precision Floats.
  | VEXTRACTPS = 810
  /// Fix Up Special Packed Float64 Values.
  | VFIXUPIMMPD = 811
  /// Fix Up Special Packed Float32 Values.
  | VFIXUPIMMPS = 812
  /// Fix Up Special Scalar Float64 Value.
  | VFIXUPIMMSD = 813
  /// Fix Up Special Scalar Float32 Value.
  | VFIXUPIMMSS = 814
  /// Fused Multiply-Add of Packed Double-Precision Floating-Point Values.
  | VFMADD132PD = 815
  /// Fused Multiply-Add of Packed Single-Precision Floating-Point Values.
  | VFMADD132PS = 816
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD132SD = 817
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD132SS = 818
  /// Fused Multiply-Add of Packed Double-Precision Floating-Point Values.
  | VFMADD213PD = 819
  /// Fused Multiply-Add of Packed Single-Precision Floating-Point Values.
  | VFMADD213PS = 820
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD213SD = 821
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD213SS = 822
  /// Fused Multiply-Add of Packed Double-Precision Floating-Point Value.
  | VFMADD231PD = 823
  /// Fused Multiply-Add of Packed Single-Precision Floating-Point Values.
  | VFMADD231PS = 824
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD231SD = 825
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD231SS = 826
  /// Fused Multiply-Alternating Add/Sub of Packed Double-Precision FP Values.
  | VFMADDSUB132PD = 827
  /// Fused Multiply-Alternating Add/Sub of Packed Single-Precision FP Values.
  | VFMADDSUB132PS = 828
  /// Fused Multiply-Alternating Add/Sub of Packed Double-Precision FP Values.
  | VFMADDSUB213PD = 829
  /// Fused Multiply-Alternating Add/Sub of Packed Single-Precision FP Values.
  | VFMADDSUB213PS = 830
  /// Fused Multiply-Alternating Add/Sub of Packed Double-Precision FP Values.
  | VFMADDSUB231PD = 831
  /// Fused Multiply-Alternating Add/Sub of Packed Single-Precision FP Values.
  | VFMADDSUB231PS = 832
  /// Fused Multiply-Subtract of Packed Double-Precision Floating-Point Values.
  | VFMSUB132PD = 833
  /// Fused Multiply-Subtract of Packed Single-Precision Floating-Point Values.
  | VFMSUB132PS = 834
  /// Fused Multiply-Subtract of Scalar Double-Precision Floating-Point Values.
  | VFMSUB132SD = 835
  /// Fused Multiply-Subtract of Scalar Single-Precision Floating-Point Values.
  | VFMSUB132SS = 836
  /// Fused Multiply-Subtract of Packed Double-Precision Floating-Point Values.
  | VFMSUB213PD = 837
  /// Fused Multiply-Subtract of Packed Single-Precision Floating-Point Values.
  | VFMSUB213PS = 838
  /// Fused Multiply-Subtract of Scalar Double-Precision Floating-Point Values.
  | VFMSUB213SD = 839
  /// Fused Multiply-Subtract of Scalar Single-Precision Floating-Point Values.
  | VFMSUB213SS = 840
  /// Fused Multiply-Subtract of Packed Double-Precision Floating-Point Values.
  | VFMSUB231PD = 841
  /// Fused Multiply-Subtract of Packed Single-Precision Floating-Point Values.
  | VFMSUB231PS = 842
  /// Fused Multiply-Subtract of Scalar Double-Precision Floating-Point Values.
  | VFMSUB231SD = 843
  /// Fused Multiply-Subtract of Scalar Single-Precision Floating-Point Values.
  | VFMSUB231SS = 844
  /// Fused Multiply-Alternating Sub/Add of Packed Double-Precision FP Values.
  | VFMSUBADD132PD = 845
  /// Fused Multiply-Alternating Sub/Add of Packed Single-Precision FP Values.
  | VFMSUBADD132PS = 846
  /// Fused Multiply-Alternating Sub/Add of Packed Double-Precision FP Values.
  | VFMSUBADD213PD = 847
  /// Fused Multiply-Alternating Sub/Add of Packed Single-Precision FP Values.
  | VFMSUBADD213PS = 848
  /// Fused Multiply-Alternating Sub/Add of Packed Double-Precision FP Values.
  | VFMSUBADD231PD = 849
  /// Fused Multiply-Alternating Sub/Add of Packed Single-Precision FP Values.
  | VFMSUBADD231PS = 850
  /// Fused Negative Multiply-Add of Packed Double-Precision FP Values.
  | VFNMADD132PD = 851
  /// Fused Negative Mul-Add of Packed Single-Precision Floating-Point Values.
  | VFNMADD132PS = 852
  /// Fused Negative Multiply-Add of Scalar Double-Precision FP Values.
  | VFNMADD132SD = 853
  /// Fused Negative Mul-Add of Scalar Single-Precision Floating-Point Values.
  | VFNMADD132SS = 854
  /// Fused Negative Multiply-Add of Packed Double-Precision FP Values.
  | VFNMADD213PD = 855
  /// Fused Negative Mul-Add of Packed Single-Precision Floating-Point Values.
  | VFNMADD213PS = 856
  /// Fused Negative Multiply-Add of Scalar Double-Precision FP Values.
  | VFNMADD213SD = 857
  /// Fused Negative Mul-Add of Scalar Single-Precision Floating-Point Values.
  | VFNMADD213SS = 858
  /// Fused Negative Multiply-Add of Packed Double-Precision FP Values.
  | VFNMADD231PD = 859
  /// Fused Negative Mul-Add of Packed Single-Precision Floating-Point Values.
  | VFNMADD231PS = 860
  /// Fused Negative Multiply-Add of Scalar Double-Precision FP Values.
  | VFNMADD231SD = 861
  /// Fused Negative Mul-Add of Scalar Single-Precision Floating-Point Values.
  | VFNMADD231SS = 862
  /// Fused Negative Multiply-Subtract of Packed Double-Precision FP Values.
  | VFNMSUB132PD = 863
  /// Fused Negative Multiply-Subtract of Packed Single-Precision FP Values.
  | VFNMSUB132PS = 864
  /// Fused Negative Multiply-Subtract of Scalar Double-Precision FP Values.
  | VFNMSUB132SD = 865
  /// Fused Negative Multiply-Subtract of Scalar Single-Precision FP Values.
  | VFNMSUB132SS = 866
  /// Fused Negative Multiply-Subtract of Packed Double-Precision FP Values.
  | VFNMSUB213PD = 867
  /// Fused Negative Multiply-Subtract of Packed Single-Precision FP Values.
  | VFNMSUB213PS = 868
  /// Fused Negative Multiply-Subtract of Scalar Double-Precision FP Values.
  | VFNMSUB213SD = 869
  /// Fused Negative Multiply-Subtract of Scalar Single-Precision FP Values.
  | VFNMSUB213SS = 870
  /// Fused Negative Multiply-Subtract of Packed Double-Precision FP Values.
  | VFNMSUB231PD = 871
  /// Fused Negative Multiply-Subtract of Packed Single-Precision FP Values.
  | VFNMSUB231PS = 872
  /// Fused Negative Multiply-Subtract of Scalar Double-Precision FP Values.
  | VFNMSUB231SD = 873
  /// Fused Negative Multiply-Subtract of Scalar Single-Precision FP Values.
  | VFNMSUB231SS = 874
  /// Tests Types Of a Packed Float64 Values.
  | VFPCLASSPD = 875
  /// Tests Types Of a Packed Float32 Values.
  | VFPCLASSPS = 876
  /// Tests Types Of a Scalar Float64 Values.
  | VFPCLASSSD = 877
  /// Tests Types Of a Scalar Float32 Values.
  | VFPCLASSSS = 878
  /// Gather Packed SP FP values Using Signed Dword/Qword Indices.
  | VGATHERDPS = 879
  /// Sparse prefetch of packed DP FP vector with T0 hint using dword indices.
  | VGATHERPF0DPD = 880
  /// Sparse prefetch of packed SP FP vector with T0 hint using dword indices.
  | VGATHERPF0DPS = 881
  /// Sparse prefetch of packed SP FP vector with T0 hint using qword indices.
  | VGATHERPF0QPS = 882
  /// Sparse prefetch of packed DP FP vector with T0 hint using qword indices.
  | VGATHERPF0QPD = 883
  /// Sparse prefetch of packed DP FP vector with T1 hint using dword indices.
  | VGATHERPF1DPD = 884
  /// Sparse prefetch of packed SP FP vector with T1 hint using dword indices.
  | VGATHERPF1DPS = 885
  /// Sparse prefetch of packed SP FP vector with T1 hint using qword indices.
  | VGATHERPF1QPS = 886
  /// Sparse prefetch of packed DP FP vector with T1 hint using qword indices.
  | VGATHERPF1QPD = 887
  /// Gather Packed DP FP Values Using Signed Dword/Qword Indices.
  | VGATHERQPD = 888
  /// Convert Exponents of Packed DP FP Values to DP FP Values.
  | VGETEXPPD = 889
  /// Convert Exponents of Packed SP FP Values to SP FP Values.
  | VGETEXPPS = 890
  /// Convert Exponents of Scalar DP FP Values to DP FP Value.
  | VGETEXPSD = 891
  /// Convert Exponents of Scalar SP FP Values to SP FP Value.
  | VGETEXPSS = 892
  /// Extract Float64 Vector of Normalized Mantissas from Float64 Vector.
  | VGETMANTPD = 893
  /// Extract Float32 Vector of Normalized Mantissas from Float32 Vector.
  | VGETMANTPS = 894
  /// Extract Float64 of Normalized Mantissas from Float64 Scalar.
  | VGETMANTSD = 895
  /// Extract Float32 Vector of Normalized Mantissa from Float32 Vector.
  | VGETMANTSS = 896
  /// Galois Field Affine Transformation Inverse.
  | VGF2P8AFFINEINVQB = 897
  /// Galois Field Affine Transformation.
  | VGF2P8AFFINEQB = 898
  /// Galois Field Multiply Bytes.
  | VGF2P8MULB = 899
  /// Packed Double-FP Horizontal Add.
  | VHADDPD = 900
  /// Packed Single-FP Horizontal Add.
  | VHADDPS = 901
  /// Packed Double-FP Horizontal Subtract.
  | VHSUBPD = 902
  /// Packed Single-FP Horizontal Subtract.
  | VHSUBPS = 903
  /// Insert Packed Floating-Point Values.
  | VINSERTF128 = 904
  /// Insert Packed Floating-Point Values.
  | VINSERTF32X4 = 905
  /// Insert Packed Floating-Point Values.
  | VINSERTF64X2 = 906
  /// Insert Packed Floating-Point Values.
  | VINSERTF64X4 = 907
  /// Insert Packed Integer Values.
  | VINSERTI128 = 908
  /// Insert 256 bits of packed doubleword integer values.
  | VINSERTI32X8 = 909
  /// Insert Packed Floating-Point Values.
  | VINSERTI64X2 = 910
  /// Insert 256 bits of packed quadword integer values.
  | VINSERTI64X4 = 911
  /// Insert Into Packed Single-Precision Floats.
  | VINSERTPS = 912
  /// Load Unaligned Integer 128 Bits.
  | VLDDQU = 913
  /// Conditional SIMD Packed Loads and Stores.
  | VMASKMOVPD = 914
  /// Conditional SIMD Packed Loads and Stores.
  | VMASKMOVPS = 915
  /// Return Maximum Packed Double-Precision Floating-Point Values.
  | VMAXPD = 916
  /// Maximum of Packed Single-Precision Floating-Point Values.
  | VMAXPS = 917
  /// Return Maximum Scalar Double-Precision Floating-Point Value.
  | VMAXSD = 918
  /// Return Maximum Scalar Single-Precision Floating-Point Value.
  | VMAXSS = 919
  /// Call to VM Monitor.
  | VMCALL = 920
  /// Clear Virtual-Machine Control Structure.
  | VMCLEAR = 921
  /// Invoke VM function.
  | VMFUNC = 922
  /// Return Minimum Packed Double-Precision Floating-Point Values.
  | VMINPD = 923
  /// Return Minimum Packed Single-Precision Floating-Point Values.
  | VMINPS = 924
  /// Return Minimum Scalar Double-Precision Floating-Point Value.
  | VMINSD = 925
  /// Return Minimum Scalar Single-Precision Floating-Point Value.
  | VMINSS = 926
  /// Launch Virtual Machine.
  | VMLAUNCH = 927
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | VMOVAPD = 928
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | VMOVAPS = 929
  /// Move Doubleword.
  | VMOVD = 930
  /// Move One Double-FP and Duplicate.
  | VMOVDDUP = 931
  /// Move Aligned Double Quadword.
  | VMOVDQA = 932
  /// Move Aligned Double Quadword.
  | VMOVDQA32 = 933
  /// Move Aligned Double Quadword.
  | VMOVDQA64 = 934
  /// Move Unaligned Double Quadword.
  | VMOVDQU = 935
  /// VMOVDQU with 16-bit granular conditional update.
  | VMOVDQU16 = 936
  /// Move Unaligned Double Quadword.
  | VMOVDQU32 = 937
  /// Move Unaligned Double Quadword.
  | VMOVDQU64 = 938
  /// VMOVDQU with 8-bit granular conditional update.
  | VMOVDQU8 = 939
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | VMOVHLPS = 940
  /// Move High Packed Double-Precision Floating-Point Value.
  | VMOVHPD = 941
  /// Move High Packed Single-Precision Floating-Point Values.
  | VMOVHPS = 942
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | VMOVLHPS = 943
  /// Move Low Packed Double-Precision Floating-Point Value.
  | VMOVLPD = 944
  /// Move Low Packed Single-Precision Floating-Point Values.
  | VMOVLPS = 945
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | VMOVMSKPD = 946
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | VMOVMSKPS = 947
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | VMOVNTDQ = 948
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPD = 949
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPS = 950
  /// Move Quadword.
  | VMOVQ = 951
  /// Move Data from String to String (doubleword).
  | VMOVSD = 952
  /// Move Packed Single-FP High and Duplicate.
  | VMOVSHDUP = 953
  /// Move Packed Single-FP Low and Duplicate.
  | VMOVSLDUP = 954
  /// Move Scalar Single-Precision Floating-Point Values.
  | VMOVSS = 955
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | VMOVUPD = 956
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | VMOVUPS = 957
  /// Load Pointer to Virtual-Machine Control Structure.
  | VMPTRLD = 958
  /// Store Pointer to Virtual-Machine Control Structure.
  | VMPTRST = 959
  /// Reads a component from the VMCS and stores it into a destination operand.
  | VMREAD = 960
  /// Resume Virtual Machine.
  | VMRESUME = 961
  /// Multiply Packed Double-Precision Floating-Point Values.
  | VMULPD = 962
  /// Multiply Packed Single-Precision Floating-Point Values.
  | VMULPS = 963
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | VMULSD = 964
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | VMULSS = 965
  /// Writes a component to the VMCS from a source operand.
  | VMWRITE = 966
  /// Leave VMX Operation.
  | VMXOFF = 967
  /// Enter VMX Operation.
  | VMXON = 968
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | VORPD = 969
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | VORPS = 970
  /// Compute Intersection Between dwords.
  | VP2INTERSECTD = 971
  /// Compute Intersection Between qwords.
  | VP2INTERSECTQ = 972
  /// Dot Product of Signed Words with Dword Accumulation.
  | VP4DPWSSD = 973
  /// Dot Product of Signed Words with Dword Accumulation and Saturation.
  | VP4DPWSSDS = 974
  /// Packed Absolute Value (byte).
  | VPABSB = 975
  /// Packed Absolute Value (dword).
  | VPABSD = 976
  /// Packed Absolute Value (qword).
  | VPABSQ = 977
  /// Packed Absolute Value (word).
  | VPABSW = 978
  /// Pack with Signed Saturation.
  | VPACKSSDW = 979
  /// Pack with Signed Saturation.
  | VPACKSSWB = 980
  /// Pack with Unsigned Saturation.
  | VPACKUSDW = 981
  /// Pack with Unsigned Saturation.
  | VPACKUSWB = 982
  /// Add Packed byte Integers.
  | VPADDB = 983
  /// Add Packed Doubleword Integers.
  | VPADDD = 984
  /// Add Packed Quadword Integers.
  | VPADDQ = 985
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | VPADDSB = 986
  /// Add Packed Signed Integers with Signed Saturation (word).
  | VPADDSW = 987
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPADDUSB = 988
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | VPADDUSW = 989
  /// Add Packed word Integers.
  | VPADDW = 990
  /// Packed Align Right.
  | VPALIGNR = 991
  /// Logical AND.
  | VPAND = 992
  /// Logical AND NOT.
  | VPANDN = 993
  /// Average Packed Integers (byte).
  | VPAVGB = 994
  /// Average Packed Integers (word).
  | VPAVGW = 995
  /// Blend Packed Dwords.
  | VPBLENDD = 996
  /// Blend Byte/Word Vectors Using an Opmask Control.
  | VPBLENDMB = 997
  /// Blend Int32/Int64 Vectors Using an OpMask Control.
  | VPBLENDMD = 998
  /// Blend qword elements using opmask as select control.
  | VPBLENDMQ = 999
  /// Blend word elements using opmask as select control.
  | VPBLENDMW = 1000
  /// Variable Blend Packed Bytes.
  | VPBLENDVB = 1001
  /// Blend Packed Words.
  | VPBLENDW = 1002
  /// Broadcast Integer Data.
  | VPBROADCASTB = 1003
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTD = 1004
  /// Broadcast Mask to Vector Register.
  | VPBROADCASTM = 1005
  /// Broadcast low byte value in k1.
  | VPBROADCASTMB2Q = 1006
  /// Broadcast low word value in k1.
  | VPBROADCASTMW2D = 1007
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTQ = 1008
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTW = 1009
  /// Carry-Less Multiplication Quadword.
  | VPCLMULQDQ = 1010
  /// Compare packed signed bytes using specified primitive.
  | VPCMPB = 1011
  /// Compare packed signed dwords using specified primitive.
  | VPCMPD = 1012
  /// Compare Packed Data for Equal (byte).
  | VPCMPEQB = 1013
  /// Compare Packed Data for Equal (doubleword).
  | VPCMPEQD = 1014
  /// Compare Packed Data for Equal (quadword).
  | VPCMPEQQ = 1015
  /// Compare Packed Data for Equal (word).
  | VPCMPEQW = 1016
  /// Packed Compare Explicit Length Strings, Return Index.
  | VPCMPESTRI = 1017
  /// Packed Compare Explicit Length Strings, Return Mask.
  | VPCMPESTRM = 1018
  /// Compare Packed Signed Integers for Greater Than (byte).
  | VPCMPGTB = 1019
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | VPCMPGTD = 1020
  /// Compare Packed Data for Greater Than (qword).
  | VPCMPGTQ = 1021
  /// Compare Packed Signed Integers for Greater Than (word).
  | VPCMPGTW = 1022
  /// Packed Compare Implicit Length Strings, Return Index.
  | VPCMPISTRI = 1023
  /// Packed Compare Implicit Length Strings, Return Mask.
  | VPCMPISTRM = 1024
  /// Compare packed signed quadwords using specified primitive.
  | VPCMPQ = 1025
  /// Compare packed unsigned bytes using specified primitive.
  | VPCMPUB = 1026
  /// Compare packed unsigned dwords using specified primitive.
  | VPCMPUD = 1027
  /// Compare packed unsigned quadwords using specified primitive.
  | VPCMPUQ = 1028
  /// Compare packed unsigned words using specified primitive.
  | VPCMPUW = 1029
  /// Compare packed signed words using specified primitive.
  | VPCMPW = 1030
  /// Compare packed unsigned bytes using specified primitive.
  | VPCMUB = 1031
  /// Compare packed unsigned dwords using specified primitive.
  | VPCMUD = 1032
  /// Compare packed unsigned quadwords using specified primitive.
  | VPCMUQ = 1033
  /// Compare packed unsigned words using specified primitive.
  | VPCMUW = 1034
  /// Store Sparse Packed Byte Integer Values into Dense Memory/Register.
  | VPCOMPRESSB = 1035
  /// Store Sparse Packed Doubleword Integer Values into Dense Memory/Register.
  | VPCOMPRESSD = 1036
  /// Store Sparse Packed Quadword Integer Values into Dense Memory/Register.
  | VPCOMPRESSQ = 1037
  /// Store Sparse Packed Word Integer Values into Dense Memory/Register.
  | VPCOMPRESSW = 1038
  /// Detect conflicts within a vector of packed 32/64-bit integers.
  | VPCONFLICTD = 1039
  /// Detect conflicts within a vector of packed 64-bit integers.
  | VPCONFLICTQ = 1040
  /// Multiply and Add Unsigned and Signed Bytes.
  | VPDPBUSD = 1041
  /// Multiply and Add Unsigned and Signed Bytes with Saturation.
  | VPDPBUSDS = 1042
  /// Multiply and Add Signed Word Integers.
  | VPDPWSSD = 1043
  /// Multiply and Add Signed Word Integers with Saturation.
  | VPDPWSSDS = 1044
  /// Permute packed bytes elements.
  | VPERMB = 1045
  /// Permute Floating-Point Values.
  | VPERM2F128 = 1046
  /// Permute Integer Values.
  | VPERM2I128 = 1047
  /// Permute Packed Doublewords/Words Elements.
  | VPERMD = 1048
  /// Full Permute of Bytes from Two Tables Overwriting the Index.
  | VPERMI2B = 1049
  /// Full permute of two tables of dword elements overwriting the index vector.
  | VPERMI2D = 1050
  /// Full permute of two tables of DP elements overwriting the index vector.
  | VPERMI2PD = 1051
  /// Full permute of two tables of SP elements overwriting the index vector.
  | VPERMI2PS = 1052
  /// Full permute of two tables of qword elements overwriting the index vector.
  | VPERMI2Q = 1053
  /// Full Permute From Two Tables Overwriting the Index.
  | VPERMI2W = 1054
  /// Permute Double-Precision Floating-Point Values.
  | VPERMILPD = 1055
  /// Permute Single-Precision Floating-Point Values.
  | VPERMILPS = 1056
  /// Permute Double-Precision Floating-Point Elements.
  | VPERMPD = 1057
  /// Permute Single-Precision Floating-Point Elements.
  | VPERMPS = 1058
  /// Qwords Element Permutation.
  | VPERMQ = 1059
  /// Full permute of two tables of byte elements overwriting one source table.
  | VPERMT2B = 1060
  /// Full permute of two tables of dword elements overwriting one source table.
  | VPERMT2D = 1061
  /// Full permute of two tables of DP elements overwriting one source table.
  | VPERMT2PD = 1062
  /// Full permute of two tables of SP elements overwriting one source table.
  | VPERMT2PS = 1063
  /// Full permute of two tables of qword elements overwriting one source table.
  | VPERMT2Q = 1064
  /// Full permute of two tables of word elements overwriting one source table.
  | VPERMT2W = 1065
  /// Permute packed word elements.
  | VPERMW = 1066
  /// Load Sparse Packed Byte Integer Values from Dense Memory / Register.
  | VPEXPANDB = 1067
  /// Load Sparse Packed Doubleword Integer Values from Dense Memory / Register.
  | VPEXPANDD = 1068
  /// Load Sparse Packed Quadword Integer Values from Dense Memory / Register.
  | VPEXPANDQ = 1069
  /// Load Sparse Packed Word Integer Values from Dense Memory / Register.
  | VPEXPANDW = 1070
  /// Extract Byte.
  | VPEXTRB = 1071
  /// Extract DWord.
  | VPEXTRD = 1072
  /// Extract Word.
  | VPEXTRW = 1073
  /// Gather packed dword values using signed Dword/Qword indices.
  | VPGATHERDD = 1074
  /// Packed Horizontal Add (32-bit).
  | VPHADDD = 1075
  /// Packed Horizontal Add and Saturate (16-bit).
  | VPHADDSW = 1076
  /// Packed Horizontal Add (16-bit).
  | VPHADDW = 1077
  /// Packed Horizontal Word Minimum.
  | VPHMINPOSUW = 1078
  /// Packed Horizontal Subtract (32-bit).
  | VPHSUBD = 1079
  /// Packed Horizontal Subtract and Saturate (16-bit).
  | VPHSUBSW = 1080
  /// Packed Horizontal Subtract (16-bit).
  | VPHSUBW = 1081
  /// Insert Byte.
  | VPINSRB = 1082
  /// Insert Dword.
  | VPINSRD = 1083
  /// Insert Qword.
  | VPINSRQ = 1084
  /// Insert Word.
  | VPINSRW = 1085
  /// Count the number of leading zero bits of packed dword elements.
  | VPLZCNTD = 1086
  /// Count the number of leading zero bits of packed qword elements.
  | VPLZCNTQ = 1087
  /// Packed Multiply of Unsigned 52-bit and Add Low 52-bit Products.
  | VPMADD52LUQ = 1088
  /// Packed Multiply of Unsigned 52-bit and Add High 52-bit Products.
  | VPMADD52HUQ = 1089
  /// Multiply and Add Packed Integers.
  | VPMADDWD = 1090
  /// Conditional SIMD Integer Packed Loads and Stores.
  | VPMASKMOVD = 1091
  /// Conditional SIMD Integer Packed Loads and Stores.
  | VPMASKMOVQ = 1092
  /// Maximum of Packed Signed Integers (byte).
  | VPMAXSB = 1093
  /// Maximum of Packed Signed Integers (dword).
  | VPMAXSD = 1094
  /// Compute maximum of packed signed 64-bit integer elements.
  | VPMAXSQ = 1095
  /// Maximum of Packed Signed Word Integers.
  | VPMAXSW = 1096
  /// Maximum of Packed Unsigned Byte Integers.
  | VPMAXUB = 1097
  /// Maximum of Packed Unsigned Integers (dword).
  | VPMAXUD = 1098
  /// Compute maximum of packed unsigned 64-bit integer elements.
  | VPMAXUQ = 1099
  /// Maximum of Packed Unsigned Integers (word).
  | VPMAXUW = 1100
  /// Minimum of Packed Signed Integers (byte).
  | VPMINSB = 1101
  /// Minimum of Packed Signed Integers (dword).
  | VPMINSD = 1102
  /// Compute minimum of packed signed 64-bit integer elements.
  | VPMINSQ = 1103
  /// Minimum of Packed Signed Word Integers.
  | VPMINSW = 1104
  /// Minimum of Packed Unsigned Byte Integers.
  | VPMINUB = 1105
  /// Minimum of Packed Dword Integers.
  | VPMINUD = 1106
  /// Compute minimum of packed unsigned 64-bit integer elements.
  | VPMINUQ = 1107
  /// Minimum of Packed Unsigned Integers (word).
  | VPMINUW = 1108
  /// Convert a vector register in 32/64-bit granularity to an opmask register.
  | VPMOVB2D = 1109
  /// Convert a Vector Register to a Mask.
  | VPMOVB2M = 1110
  /// Convert dword vector register to mask register.
  | VPMOVD2M = 1111
  /// Down Convert DWord to Byte.
  | VPMOVDB = 1112
  /// Down Convert DWord to Word.
  | VPMOVDW = 1113
  /// Convert opmask register to vector register in 8-bit granularity.
  | VPMOVM2B = 1114
  /// Convert opmask register to vector register in 32-bit granularity.
  | VPMOVM2D = 1115
  /// Convert opmask register to vector register in 64-bit granularity.
  | VPMOVM2Q = 1116
  /// Convert opmask register to vector register in 16-bit granularity.
  | VPMOVM2W = 1117
  /// Move Byte Mask.
  | VPMOVMSKB = 1118
  /// Convert qword vector register to mask register.
  | VPMOVQ2M = 1119
  /// Down Convert QWord to Byte.
  | VPMOVQB = 1120
  /// Down Convert QWord to DWord.
  | VPMOVQD = 1121
  /// Down Convert QWord to Word.
  | VPMOVQW = 1122
  /// Down Convert DWord to Byte.
  | VPMOVSDB = 1123
  /// Down Convert DWord to Word.
  | VPMOVSDW = 1124
  /// Down Convert QWord to Byte.
  | VPMOVSQB = 1125
  /// Down Convert QWord to Dword.
  | VPMOVSQD = 1126
  /// Down Convert QWord to Word.
  | VPMOVSQW = 1127
  /// Down Convert Word to Byte.
  | VPMOVSWB = 1128
  /// Packed Move with Sign Extend (8-bit to 32-bit).
  | VPMOVSXBD = 1129
  /// Packed Move with Sign Extend (8-bit to 64-bit).
  | VPMOVSXBQ = 1130
  /// Packed Move with Sign Extend (8-bit to 16-bit).
  | VPMOVSXBW = 1131
  /// Packed Move with Sign Extend (32-bit to 64-bit).
  | VPMOVSXDQ = 1132
  /// Packed Move with Sign Extend (16-bit to 32-bit).
  | VPMOVSXWD = 1133
  /// Packed Move with Sign Extend (16-bit to 64-bit).
  | VPMOVSXWQ = 1134
  /// Down Convert DWord to Byte.
  | VPMOVUSDB = 1135
  /// Down Convert DWord to Word.
  | VPMOVUSDW = 1136
  /// Down Convert QWord to Byte.
  | VPMOVUSQB = 1137
  /// Down Convert QWord to DWord.
  | VPMOVUSQD = 1138
  /// Down Convert QWord to Word.
  | VPMOVUSQW = 1139
  /// Down Convert Word to Byte.
  | VPMOVUSWB = 1140
  /// Convert a vector register in 16-bit granularity to an opmask register.
  | VPMOVW2M = 1141
  /// Down convert word elements in a vector to byte elements using truncation.
  | VPMOVWB = 1142
  /// Packed Move with Zero Extend (8-bit to 32-bit).
  | VPMOVZXBD = 1143
  /// Packed Move with Zero Extend (8-bit to 64-bit).
  | VPMOVZXBQ = 1144
  /// Packed Move with Zero Extend (8-bit to 16-bit).
  | VPMOVZXBW = 1145
  /// Packed Move with Zero Extend (32-bit to 64-bit).
  | VPMOVZXDQ = 1146
  /// Packed Move with Zero Extend (16-bit to 32-bit).
  | VPMOVZXWD = 1147
  /// Packed Move with Zero Extend (16-bit to 64-bit).
  | VPMOVZXWQ = 1148
  /// Multiply Packed Doubleword Integers.
  | VPMULDQ = 1149
  /// Packed Multiply High with Round and Scale.
  | VPMULHRSW = 1150
  /// Multiply Packed Unsigned Integers and Store High Result.
  | VPMULHUW = 1151
  /// Multiply Packed Signed Integers and Store High Result.
  | VPMULHW = 1152
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLD = 1153
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLQ = 1154
  /// Multiply Packed Signed Integers and Store Low Result.
  | VPMULLW = 1155
  /// Select Packed Unaligned Bytes from Quadword Sources.
  | VPMULTISHIFTQB = 1156
  /// Multiply Packed Unsigned Doubleword Integers.
  | VPMULUDQ = 1157
  /// Return the Count of Number of Bits Set to 1 in byte.
  | VPOPCNTB = 1158
  /// Return the Count of Number of Bits Set to 1 in dword.
  | VPOPCNTD = 1159
  /// Return the Count of Number of Bits Set to 1 in qword.
  | VPOPCNTQ = 1160
  /// Return the Count of Number of Bits Set to 1 in word.
  | VPOPCNTW = 1161
  /// Bitwise Logical OR.
  | VPOR = 1162
  /// Rotate dword elem left by a constant shift count with conditional update.
  | VPROLD = 1163
  /// Rotate qword elem left by a constant shift count with conditional update.
  | VPROLQ = 1164
  /// Rotate dword element left by shift counts specified.
  | VPROLVD = 1165
  /// Rotate qword element left by shift counts specified.
  | VPROLVQ = 1166
  /// Rotate dword element right by a constant shift count.
  | VPRORD = 1167
  /// Rotate qword element right by a constant shift count.
  | VPRORQ = 1168
  /// Rotate dword element right by shift counts specified.
  | VPRORRD = 1169
  /// Rotate qword element right by shift counts specified.
  | VPRORRQ = 1170
  /// Rotate dword element right by shift counts specified.
  | VPRORVD = 1171
  /// Rotate qword element right by shift counts specified.
  | VPRORVQ = 1172
  /// Compute Sum of Absolute Differences.
  | VPSADBW = 1173
  /// Scatter dword elements in a vector to memory using dword indices.
  | VPSCATTERDD = 1174
  /// Scatter qword elements in a vector to memory using dword indices.
  | VPSCATTERDQ = 1175
  /// Scatter dword elements in a vector to memory using qword indices.
  | VPSCATTERQD = 1176
  /// Scatter qword elements in a vector to memory using qword indices.
  | VPSCATTERQQ = 1177
  /// Concatenate and Shift Packed Data Left Logical.
  | VPSHLD = 1178
  /// Concatenate and Variable Shift Packed Data Left Logical.
  | VPSHLDV = 1179
  /// Concatenate and Shift Packed Data Right Logical.
  | VPSHRD = 1180
  /// Concatenate and Variable Shift Packed Data Right Logical.
  | VPSHRDV = 1181
  /// Packed Shuffle Bytes.
  | VPSHUFB = 1182
  /// Shuffle Bits from Quadword Elements Using Byte Indexes into Mask.
  | VPSHUFBITQMB = 1183
  /// Shuffle Packed Doublewords.
  | VPSHUFD = 1184
  /// Shuffle Packed High Words.
  | VPSHUFHW = 1185
  /// Shuffle Packed Low Words.
  | VPSHUFLW = 1186
  /// Packed SIGN (byte).
  | VPSIGNB = 1187
  /// Packed SIGN (doubleword).
  | VPSIGND = 1188
  /// Packed SIGN (word).
  | VPSIGNW = 1189
  /// Shift Packed Data Left Logical (doubleword).
  | VPSLLD = 1190
  /// Shift Double Quadword Left Logical.
  | VPSLLDQ = 1191
  /// Shift Packed Data Left Logical (quadword).
  | VPSLLQ = 1192
  /// Variable Bit Shift Left Logical.
  | VPSLLVD = 1193
  /// Variable Bit Shift Left Logical.
  | VPSLLVQ = 1194
  /// Variable Bit Shift Left Logical.
  | VPSLLVW = 1195
  /// Shift Packed Data Left Logical (word).
  | VPSLLW = 1196
  /// Shift Packed Data Right Arithmetic (doubleword).
  | VPSRAD = 1197
  /// Shift qwords right by a constant shift count and shifting in sign bits.
  | VPSRAQ = 1198
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVD = 1199
  /// Shift qwords right by shift counts in a vector and shifting in sign bits.
  | VPSRAVQ = 1200
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVW = 1201
  /// Shift Packed Data Right Arithmetic (word).
  | VPSRAW = 1202
  /// Shift Packed Data Right Logical (doubleword).
  | VPSRLD = 1203
  /// Shift Double Quadword Right Logical.
  | VPSRLDQ = 1204
  /// Shift Packed Data Right Logical (quadword).
  | VPSRLQ = 1205
  /// Variable Bit Shift Right Logical.
  | VPSRLVD = 1206
  /// Variable Bit Shift Right Logical.
  | VPSRLVQ = 1207
  /// Variable Bit Shift Right Logical.
  | VPSRLVW = 1208
  /// Shift Packed Data Right Logical (word).
  | VPSRLW = 1209
  /// Subtract Packed Integers (byte).
  | VPSUBB = 1210
  /// Subtract Packed Integers (doubleword).
  | VPSUBD = 1211
  /// Subtract Packed Integers (quadword).
  | VPSUBQ = 1212
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | VPSUBSB = 1213
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | VPSUBSW = 1214
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPSUBUSB = 1215
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | VPSUBUSW = 1216
  /// Subtract Packed Integers (word).
  | VPSUBW = 1217
  /// Perform bitwise ternary logic operation of three vectors.
  | VPTERLOGD = 1218
  /// Perform bitwise ternary logic operation of three vectors.
  | VPTERLOGQ = 1219
  /// Bitwise Ternary Logic.
  | VPTERNLOGD = 1220
  /// Bitwise Ternary Logic.
  | VPTERNLOGQ = 1221
  /// Logical Compare.
  | VPTEST = 1222
  /// Perform bitwise AND of byte elems of two vecs and write results to opmask.
  | VPTESTMB = 1223
  /// Perform bitwise AND of dword elems of 2-vecs and write results to opmask.
  | VPTESTMD = 1224
  /// Perform bitwise AND of qword elems of 2-vecs and write results to opmask.
  | VPTESTMQ = 1225
  /// Perform bitwise AND of word elems of two vecs and write results to opmask.
  | VPTESTMW = 1226
  /// Perform bitwise NAND of byte elems of 2-vecs and write results to opmask.
  | VPTESTNMB = 1227
  /// Perform bitwise NAND of dword elems of 2-vecs and write results to opmask.
  | VPTESTNMD = 1228
  /// Perform bitwise NAND of qword elems of 2-vecs and write results to opmask.
  | VPTESTNMQ = 1229
  /// Perform bitwise NAND of word elems of 2-vecs and write results to opmask.
  | VPTESTNMW = 1230
  /// Unpack High Data.
  | VPUNPCKHBW = 1231
  /// Unpack High Data.
  | VPUNPCKHDQ = 1232
  /// Unpack High Data.
  | VPUNPCKHQDQ = 1233
  /// Unpack High Data.
  | VPUNPCKHWD = 1234
  /// Unpack Low Data.
  | VPUNPCKLBW = 1235
  /// Unpack Low Data.
  | VPUNPCKLDQ = 1236
  /// Unpack Low Data.
  | VPUNPCKLQDQ = 1237
  /// Unpack Low Data.
  | VPUNPCKLWD = 1238
  /// Logical Exclusive OR.
  | VPXOR = 1239
  /// Bitwise XOR of packed doubleword integers.
  | VPXORD = 1240
  /// Bitwise XOR of packed quadword integers.
  | VPXORQ = 1241
  /// Range Restriction Calculation For Packed Pairs of Float64 Values.
  | VRANGEPD = 1242
  /// Range Restriction Calculation For Packed Pairs of Float32 Values.
  | VRANGEPS = 1243
  /// Range Restriction Calculation From a pair of Scalar Float64 Values.
  | VRANGESD = 1244
  /// Range Restriction Calculation From a Pair of Scalar Float32 Values.
  | VRANGESS = 1245
  /// Compute Approximate Reciprocals of Packed Float64 Values.
  | VRCP14PD = 1246
  /// Compute Approximate Reciprocals of Packed Float32 Values.
  | VRCP14PS = 1247
  /// Compute Approximate Reciprocal of Scalar Float64 Value.
  | VRCP14SD = 1248
  /// Compute Approximate Reciprocal of Scalar Float32 Value.
  | VRCP14SS = 1249
  /// Computes the reciprocal approximation of the float64 values.
  | VRCP28PD = 1250
  /// Computes the reciprocal approximation of the float32 values.
  | VRCP28PS = 1251
  /// Computes the reciprocal approximation of the low float64 value.
  | VRCP28SD = 1252
  /// Computes the reciprocal approximation of the low float32 value.
  | VRCP28SS = 1253
  /// Compute reciprocals of packed single-precision floating-point values.
  | VRCPPS = 1254
  /// Compute Reciprocal of Scalar Single-Precision Floating-Point Values.
  | VRCPSS = 1255
  /// Perform Reduction Transformation on Packed Float64 Values.
  | VREDUCEPD = 1256
  /// Perform Reduction Transformation on Packed Float32 Values.
  | VREDUCEPS = 1257
  /// Perform a Reduction Transformation on a Scalar Float64 Value.
  | VREDUCESD = 1258
  /// Perform a Reduction Transformation on a Scalar Float32 Value.
  | VREDUCESS = 1259
  /// Round Packed Float64 Values To Include A Given Number Of Fraction Bits.
  | VRNDSCALEPD = 1260
  /// Round Packed Float32 Values To Include A Given Number Of Fraction Bits.
  | VRNDSCALEPS = 1261
  /// Round Scalar Float64 Value To Include A Given Number Of Fraction Bits.
  | VRNDSCALESD = 1262
  /// Round Scalar Float32 Value To Include A Given Number Of Fraction Bits.
  | VRNDSCALESS = 1263
  /// Round Packed Double-Precision Values.
  | VROUNDPD = 1264
  /// Round Packed Single-Precision Values.
  | VROUNDPS = 1265
  /// Round Scalar Double-Precision Value.
  | VROUNDSD = 1266
  /// Round Scalar Single-Precision Value.
  | VROUNDSS = 1267
  /// Compute Approximate Reciprocals of Square Roots of Packed Float64 Values.
  | VRSQRT14PD = 1268
  /// Compute Approximate Reciprocals of Square Roots of Packed Float32 Values.
  | VRSQRT14PS = 1269
  /// Compute Approximate Reciprocal of Square Root of Scalar Float64 Value.
  | VRSQRT14SD = 1270
  /// Compute Approximate Reciprocal of Square Root of Scalar Float32 Value.
  | VRSQRT14SS = 1271
  /// Computes the reciprocal square root of the float64 values.
  | VRSQRT28PD = 1272
  /// Computes the reciprocal square root of the float32 values.
  | VRSQRT28PS = 1273
  /// Computes the reciprocal square root of the low float64 value.
  | VRSQRT28SD = 1274
  /// Computes the reciprocal square root of the low float32 value.
  | VRSQRT28SS = 1275
  /// Compute Reciprocals of Square Roots of Packed Single-Precision FP Values.
  | VRSQRTPS = 1276
  /// Compute Reciprocal of Square Root of Scalar Single-Precision FP Value.
  | VRSQRTSS = 1277
  /// Scale Packed Float64 Values With Float64 Values.
  | VSCALEFPD = 1278
  /// Scale Packed Float32 Values With Float32 Values.
  | VSCALEFPS = 1279
  /// Scale Scalar Float64 Values With Float64 Values.
  | VSCALEFSD = 1280
  /// Scale Scalar Float32 Value With Float32 Value.
  | VSCALEFSS = 1281
  /// Multiply packed DP FP elements of a vector by powers.
  | VSCALEPD = 1282
  /// Multiply packed SP FP elements of a vector by powers.
  | VSCALEPS = 1283
  /// Multiply the low DP FP element of a vector by powers.
  | VSCALESD = 1284
  /// Multiply the low SP FP element of a vector by powers.
  | VSCALESS = 1285
  /// Scatter SP/DP FP elements in a vector to memory using dword indices.
  | VSCATTERDD = 1286
  /// Scatter packed double with signed dword indices.
  | VSCATTERDPD = 1287
  /// Scatter packed single with signed dword indices.
  | VSCATTERDPS = 1288
  /// Scatter SP/DP FP elements in a vector to memory using dword indices.
  | VSCATTERDQ = 1289
  /// Scatter packed double with signed qword indices.
  | VSCATTERQPD = 1290
  /// Scatter packed single with signed qword indices.
  | VSCATTERQPS = 1291
  /// Sparse prefetch packed DP FP with T0 hint to write using dword indices.
  | VSCATTERPF0DPD = 1292
  /// Sparse prefetch packed SP FP with T0 hint to write using dword indices.
  | VSCATTERPF0DPS = 1293
  /// Sparse prefetch packed SP FP with T0 hint to write using qword indices.
  | VSCATTERPF0QPS = 1294
  /// Sparse prefetch packed DP FP with T0 hint to write using qword indices.
  | VSCATTERPF0QPD = 1295
  /// Sparse prefetch packed DP FP with T1 hint to write using dword indices.
  | VSCATTERPF1DPD = 1296
  /// Sparse prefetch packed SP FP with T1 hint to write using dword indices.
  | VSCATTERPF1DPS = 1297
  /// Sparse prefetch packed SP FP with T1 hint to write using qword indices.
  | VSCATTERPF1QPS = 1298
  /// Sparse prefetch packed DP FP with T1 hint to write using qword indices.
  | VSCATTERPF1QPD = 1299
  /// Scatter SP/DP FP elements in a vector to memory using qword indices.
  | VSCATTERQD = 1300
  /// Scatter SP/DP FP elements in a vector to memory using qword indices.
  | VSCATTERQQ = 1301
  /// Shuffle 128-bit lanes of a vector with 32 bit granular conditional update.
  | VSHUFF32X4 = 1302
  /// Shuffle 128-bit lanes of a vector with 64 bit granular conditional update.
  | VSHUFF64X2 = 1303
  /// Shuffle 128-bit lanes of a vector with 32 bit granular conditional update.
  | VSHUFI32X4 = 1304
  /// Shuffle 128-bit lanes of a vector with 64 bit granular conditional update.
  | VSHUFI64X2 = 1305
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | VSHUFPD = 1306
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | VSHUFPS = 1307
  /// Compute packed square roots of packed double-precision FP values.
  | VSQRTPD = 1308
  /// Compute square roots of packed single-precision floating-point values.
  | VSQRTPS = 1309
  /// Compute scalar square root of scalar double-precision FP values.
  | VSQRTSD = 1310
  /// Compute square root of scalar single-precision floating-point values.
  | VSQRTSS = 1311
  /// Subtract Packed Double-Precision Floating-Point Values.
  | VSUBPD = 1312
  /// Subtract Packed Single-Precision Floating-Point Values.
  | VSUBPS = 1313
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | VSUBSD = 1314
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | VSUBSS = 1315
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | VUCOMISD = 1316
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | VUCOMISS = 1317
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | VUNPCKHPD = 1318
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | VUNPCKHPS = 1319
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | VUNPCKLPD = 1320
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | VUNPCKLPS = 1321
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | VXORPD = 1322
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | VXORPS = 1323
  /// Zero Upper Bits of YMM Registers.
  | VZEROUPPER = 1324
  /// Wait.
  | WAIT = 1325
  /// Write Back and Invalidate Cache.
  | WBINVD = 1326
  /// Write FS Segment Base.
  | WRFSBASE = 1327
  /// Write GS Segment Base.
  | WRGSBASE = 1328
  /// Write to Model Specific Register.
  | WRMSR = 1329
  /// Write Data to User Page Key Register.
  | WRPKRU = 1330
  /// Write to a shadow stack.
  | WRSSD = 1331
  /// Write to a shadow stack.
  | WRSSQ = 1332
  /// Write to a user mode shadow stack.
  | WRUSSD = 1333
  /// Write to a user mode shadow stack.
  | WRUSSQ = 1334
  /// Transactional Abort.
  | XABORT = 1335
  /// Prefix hint to the beginning of an HLE transaction region.
  | XACQUIRE = 1336
  /// Exchange and Add.
  | XADD = 1337
  /// Transactional Begin.
  | XBEGIN = 1338
  /// Exchange Register/Memory with Register.
  | XCHG = 1339
  /// Transactional End.
  | XEND = 1340
  /// Value of Extended Control Register.
  | XGETBV = 1341
  /// Table lookup translation.
  | XLAT = 1342
  /// Table Look-up Translation.
  | XLATB = 1343
  /// Logical Exclusive OR.
  | XOR = 1344
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | XORPD = 1345
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | XORPS = 1346
  /// Prefix hint to the end of an HLE transaction region.
  | XRELEASE = 1347
  /// Restore Processor Extended States.
  | XRSTOR = 1348
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS = 1349
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS64 = 1350
  /// Save Processor Extended States.
  | XSAVE = 1351
  /// Save processor extended states with compaction to memory.
  | XSAVEC = 1352
  /// Save processor extended states with compaction to memory.
  | XSAVEC64 = 1353
  /// Save Processor Extended States Optimized.
  | XSAVEOPT = 1354
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES = 1355
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES64 = 1356
  /// Set Extended Control Register.
  | XSETBV = 1357
  /// Test If In Transactional Execution.
  | XTEST = 1358
  /// Invalid Opcode.
  | InvalOP = 1359

// vim: set tw=80 sts=2 sw=2:
