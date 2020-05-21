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

open B2R2

/// This is a fatal error that happens when B2R2 tries to access non-existing
/// register symbol. This exception should not happen in general.
exception internal InvalidRegAccessException

exception internal InvalidPrefixException

exception internal InvalidOn64Exception

/// Instruction prefixes.
type Prefix =
  | PrxNone = 0x0       (* No prefix *)
  | PrxLOCK = 0x1       (* Group 1 *)
  /// REPNE/REPNZ prefix is encoded using F2H.
  | PrxREPNZ = 0x2
  /// REP or REPE/REPZ is encoded using F3H.
  | PrxREPZ = 0x4
  | PrxCS = 0x8         (* Group 2 *)
  | PrxSS = 0x10
  | PrxDS = 0x20
  | PrxES = 0x40
  | PrxFS = 0x80
  | PrxGS = 0x100
  /// Operand-size override prefix is encoded using 66H.
  | PrxOPSIZE = 0x200   (* Group 3 *)
  /// 67H - Address-size override prefix.
  | PrxADDRSIZE = 0x400 (* Group 4 *)

/// REX prefixes.
type REXPrefix =
  /// No REX: this is to represent the case where there is no REX
  | NOREX   = 0b0000000
  /// Extension of the ModR/M reg, Opcode reg field (SPL, BPL, ...).
  | REX     = 0b1000000
  /// Extension of the ModR/M rm, SIB base, Opcode reg field.
  | REXB    = 0b1000001
  /// Extension of the SIB index field.
  | REXX    = 0b1000010
  /// Extension of the ModR/M SIB index, base field.
  | REXXB   = 0b1000011
  /// Extension of the ModR/M reg field.
  | REXR    = 0b1000100
  /// Extension of the ModR/M reg, r/m field.
  | REXRB   = 0b1000101
  /// Extension of the ModR/M reg, SIB index field.
  | REXRX   = 0b1000110
  /// Extension of the ModR/M reg, SIB index, base.
  | REXRXB  = 0b1000111
  /// Operand 64bit.
  | REXW    = 0b1001000
  /// REX.B + Operand 64bit.
  | REXWB   = 0b1001001
  /// REX.X + Operand 64bit.
  | REXWX   = 0b1001010
  /// REX.XB + Operand 64bit.
  | REXWXB  = 0b1001011
  /// REX.R + Operand 64bit.
  | REXWR   = 0b1001100
  /// REX.RB + Operand 64bit.
  | REXWRB  = 0b1001101
  /// REX.RX + Operand 64bit.
  | REXWRX  = 0b1001110
  /// REX.RXB + Operand 64bit.
  | REXWRXB = 0b1001111

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
  /// Compute 2x-1.
  | F2XM1 = 140
  /// Absolute Value.
  | FABS = 141
  /// Add.
  | FADD = 142
  /// Add and pop the register stack.
  | FADDP = 143
  /// Load Binary Coded Decimal.
  | FBLD = 144
  /// Store BCD Integer and Pop.
  | FBSTP = 145
  /// Change Sign.
  | FCHS = 146
  /// Clear Exceptions.
  | FCLEX = 147
  /// Floating-Point Conditional Move (if below (CF = 1)).
  | FCMOVB = 148
  /// Floating-Point Conditional Move (if below or equal (CF = 1 or ZF = 1)).
  | FCMOVBE = 149
  /// Floating-Point Conditional Move (if equal (ZF = 1)).
  | FCMOVE = 150
  /// Floating-Point Conditional Move (if not below (CF = 0)).
  | FCMOVNB = 151
  /// FP Conditional Move (if not below or equal (CF = 0 and ZF = 0)).
  | FCMOVNBE = 152
  /// Floating-Point Conditional Move (if not equal (ZF = 0)).
  | FCMOVNE = 153
  /// Floating-Point Conditional Move (if not unordered (PF = 0)).
  | FCMOVNU = 154
  /// Floating-Point Conditional Move (if unordered (PF = 1)).
  | FCMOVU = 155
  /// Compare Floating Point Values.
  | FCOM = 156
  /// Compare Floating Point Values and Set EFLAGS.
  | FCOMI = 157
  /// Compare Floating Point Values and Set EFLAGS.
  | FCOMIP = 158
  /// Compare Floating Point Values and pop register stack.
  | FCOMP = 159
  /// Compare Floating Point Values and pop register stack twice.
  | FCOMPP = 160
  /// Cosine.
  | FCOS = 161
  /// Decrement Stack-Top Pointer.
  | FDECSTP = 162
  /// Divide.
  | FDIV = 163
  /// Divide and pop the register stack.
  | FDIVP = 164
  /// Reverse Divide.
  | FDIVR = 165
  /// Reverse Divide and pop the register stack.
  | FDIVRP = 166
  /// Free Floating-Point Register.
  | FFREE = 167
  /// Add.
  | FIADD = 168
  /// Compare Integer.
  | FICOM = 169
  /// Compare Integer and pop the register stack.
  | FICOMP = 170
  /// Divide.
  | FIDIV = 171
  /// Reverse Divide.
  | FIDIVR = 172
  /// Load Integer.
  | FILD = 173
  /// Multiply.
  | FIMUL = 174
  /// Increment Stack-Top Pointer.
  | FINCSTP = 175
  /// Initialize Floating-Point Unit.
  | FINIT = 176
  /// Store Integer.
  | FIST = 177
  /// Store Integer and pop the register stack.
  | FISTP = 178
  /// Store Integer with Truncation.
  | FISTTP = 179
  /// Subtract.
  | FISUB = 180
  /// Reverse Subtract.
  | FISUBR = 181
  /// Load Floating Point Value.
  | FLD = 182
  /// Load Constant (Push +1.0 onto the FPU register stack).
  | FLD1 = 183
  /// Load x87 FPU Control Word.
  | FLDCW = 184
  /// Load x87 FPU Environment.
  | FLDENV = 185
  /// Load Constant (Push log2e onto the FPU register stack).
  | FLDL2E = 186
  /// Load Constant (Push log210 onto the FPU register stack).
  | FLDL2T = 187
  /// Load Constant (Push log102 onto the FPU register stack).
  | FLDLG2 = 188
  /// Load Constant (Push loge2 onto the FPU register stack).
  | FLDLN2 = 189
  /// Load Constant (Push Pi onto the FPU register stack).
  | FLDPI = 190
  /// Load Constant (Push +0.0 onto the FPU register stack).
  | FLDZ = 191
  /// Multiply.
  | FMUL = 192
  /// Multiply and pop the register stack.
  | FMULP = 193
  /// Clear floating-point exception flags without checking for error conditions.
  | FNCLEX = 194
  /// Initialize FPU without checking error conditions.
  | FNINIT = 195
  /// No Operation.
  | FNOP = 196
  /// Save FPU state without checking error conditions.
  | FNSAVE = 197
  /// Store x87 FPU Control Word.
  | FNSTCW = 198
  /// Store FPU environment without checking error conditions.
  | FNSTENV = 199
  /// Store FPU status word without checking error conditions.
  | FNSTSW = 200
  /// Partial Arctangent.
  | FPATAN = 201
  /// Partial Remainder.
  | FPREM = 202
  /// Partial Remainder.
  | FPREM1 = 203
  /// Partial Tangent.
  | FPTAN = 204
  /// Round to Integer.
  | FRNDINT = 205
  /// Restore x87 FPU State.
  | FRSTOR = 206
  /// Store x87 FPU State.
  | FSAVE = 207
  /// Scale.
  | FSCALE = 208
  /// Sine.
  | FSIN = 209
  /// Sine and Cosine.
  | FSINCOS = 210
  /// Square Root.
  | FSQRT = 211
  /// Store Floating Point Value.
  | FST = 212
  /// Store FPU control word after checking error conditions.
  | FSTCW = 213
  /// Store x87 FPU Environment.
  | FSTENV = 214
  /// Store Floating Point Value.
  | FSTP = 215
  /// Store x87 FPU Status Word.
  | FSTSW = 216
  /// Subtract.
  | FSUB = 217
  /// Subtract and pop register stack.
  | FSUBP = 218
  /// Reverse Subtract.
  | FSUBR = 219
  /// Reverse Subtract and pop register stack.
  | FSUBRP = 220
  /// TEST.
  | FTST = 221
  /// Unordered Compare Floating Point Values.
  | FUCOM = 222
  /// Compare Floating Point Values and Set EFLAGS.
  | FUCOMI = 223
  /// Compare Floating Point Values and Set EFLAGS and pop register stack.
  | FUCOMIP = 224
  /// Unordered Compare Floating Point Values.
  | FUCOMP = 225
  /// Unordered Compare Floating Point Values.
  | FUCOMPP = 226
  /// Wait for FPU.
  | FWAIT = 227
  /// Examine ModR/M.
  | FXAM = 228
  /// Exchange Register Contents.
  | FXCH = 229
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR = 230
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR64 = 231
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE = 232
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE64 = 233
  /// Extract Exponent and Significand.
  | FXTRACT = 234
  /// compute y * log2x.
  | FYL2X = 235
  /// compute y * log2(x+1).
  | FYL2XP1 = 236
  /// GETSEC.
  | GETSEC = 237
  /// Galois Field Affine Transformation Inverse.
  | GF2P8AFFINEINVQB = 238
  /// Galois Field Affine Transformation.
  | GF2P8AFFINEQB = 239
  /// Galois Field Multiply Bytes.
  | GF2P8MULB = 240
  /// Packed Double-FP Horizontal Add.
  | HADDPD = 241
  /// Packed Single-FP Horizontal Add.
  | HADDPS = 242
  /// Halt.
  | HLT = 243
  /// Packed Double-FP Horizontal Subtract.
  | HSUBPD = 244
  /// Packed Single-FP Horizontal Subtract.
  | HSUBPS = 245
  /// Signed Divide.
  | IDIV = 246
  /// Signed Multiply.
  | IMUL = 247
  /// Input from Port.
  | IN = 248
  /// Increment by 1.
  | INC = 249
  /// Increment the shadow stack pointer (SSP).
  | INCSSP = 250
  /// Input from Port to String.
  | INS = 251
  /// Input from Port to String (byte).
  | INSB = 252
  /// Input from Port to String (doubleword).
  | INSD = 253
  /// Insert Scalar Single-Precision Floating-Point Value.
  | INSERTPS = 254
  /// Input from Port to String (word).
  | INSW = 255
  /// Call to Interrupt (Interrupt vector specified by immediate byte).
  | INT = 256
  /// Call to Interrupt (Interrupt 3?trap to debugger).
  | INT3 = 257
  /// Call to Interrupt (InteInterrupt 4?if overflow flag is 1).
  | INTO = 258
  /// Invalidate Internal Caches.
  | INVD = 259
  /// Invalidate Translations Derived from EPT.
  | INVEPT = 260
  /// Invalidate TLB Entries.
  | INVLPG = 261
  /// Invalidate Process-Context Identifier.
  | INVPCID = 262
  /// Invalidate Translations Based on VPID.
  | INVVPID = 263
  /// Return from interrupt.
  | IRET = 264
  /// Interrupt return (32-bit operand size).
  | IRETD = 265
  /// Interrupt return (64-bit operand size).
  | IRETQ = 266
  /// Interrupt return (16-bit operand size).
  | IRETW = 267
  /// Jump if Condition Is Met (Jump short if above, CF = 0 and ZF = 0).
  | JNBE = 268
  | JA = 268
  /// Jump if Condition Is Met (Jump short if below, CF = 1).
  | JC = 269
  | JNAE = 269
  | JB = 269
  /// Jump if Condition Is Met (Jump short if below or equal, CF = 1 or ZF).
  | JNA = 270
  | JBE = 270
  /// Jump if Condition Is Met (Jump short if CX register is 0).
  | JCXZ = 271
  /// Jump if Condition Is Met (Jump short if ECX register is 0).
  | JECXZ = 272
  /// Jump if Condition Is Met (Jump short if RCX register is 0).
  | JRCXZ = 273
  /// Jump if Condition Is Met (Jump short if greater, ZF = 0 and SF = OF).
  | JNLE = 274
  | JG = 274
  /// Jump if Condition Is Met (Jump short if less, SF <> OF).
  | JNGE = 275
  | JL = 275
  /// Jump if Cond Is Met (Jump short if less or equal, ZF = 1 or SF <> OF).
  | JNG = 276
  | JLE = 276
  /// Far jmp.
  | JMPFar = 277
  /// Near jmp.
  | JMPNear = 278
  /// Jump if Condition Is Met (Jump near if not below, CF = 0).
  | JAE = 279
  | JNC = 279
  | JNB = 279
  /// Jump if Condition Is Met (Jump near if not less, SF = OF).
  | JGE = 280
  | JNL = 280
  /// Jump if Condition Is Met (Jump near if not overflow, OF = 0).
  | JNO = 281
  /// Jump if Condition Is Met (Jump near if not parity, PF = 0).
  | JPO = 282
  | JNP = 282
  /// Jump if Condition Is Met (Jump near if not sign, SF = 0).
  | JNS = 283
  /// Jump if Condition Is Met (Jump near if not zero, ZF = 0).
  | JNZ = 284
  | JNE = 284
  /// Jump if Condition Is Met (Jump near if overflow, OF = 1).
  | JO = 285
  /// Jump if Condition Is Met (Jump near if parity, PF = 1).
  | JP = 286
  | JPE = 286
  /// Jump if Condition Is Met (Jump short if sign, SF = 1).
  | JS = 287
  /// Jump if Condition Is Met (Jump short if zero, ZF = 1).
  | JZ = 288
  | JE = 288
  /// Add two 8-bit opmasks.
  | KADDB = 289
  /// Add two 32-bit opmasks.
  | KADDD = 290
  /// Add two 64-bit opmasks.
  | KADDQ = 291
  /// Add two 16-bit opmasks.
  | KADDW = 292
  /// Logical AND two 8-bit opmasks.
  | KANDB = 293
  /// Logical AND two 32-bit opmasks.
  | KANDD = 294
  /// Logical AND NOT two 8-bit opmasks.
  | KANDNB = 295
  /// Logical AND NOT two 32-bit opmasks.
  | KANDND = 296
  /// Logical AND NOT two 64-bit opmasks.
  | KANDNQ = 297
  /// Logical AND NOT two 16-bit opmasks.
  | KANDNW = 298
  /// Logical AND two 64-bit opmasks.
  | KANDQ = 299
  /// Logical AND two 16-bit opmasks.
  | KANDW = 300
  /// Move from or move to opmask register of 8-bit data.
  | KMOVB = 301
  /// Move from or move to opmask register of 32-bit data.
  | KMOVD = 302
  /// Move from or move to opmask register of 64-bit data.
  | KMOVQ = 303
  /// Move from or move to opmask register of 16-bit data.
  | KMOVW = 304
  /// Bitwise NOT of two 8-bit opmasks.
  | KNOTB = 305
  /// Bitwise NOT of two 32-bit opmasks.
  | KNOTD = 306
  /// Bitwise NOT of two 64-bit opmasks.
  | KNOTQ = 307
  /// Bitwise NOT of two 16-bit opmasks.
  | KNOTW = 308
  /// Logical OR two 8-bit opmasks.
  | KORB = 309
  /// Logical OR two 32-bit opmasks.
  | KORD = 310
  /// Logical OR two 64-bit opmasks.
  | KORQ = 311
  /// Update EFLAGS according to the result of bitwise OR of two 8-bit opmasks.
  | KORTESTB = 312
  /// Update EFLAGS according to the result of bitwise OR of two 32-bit opmasks.
  | KORTESTD = 313
  /// Update EFLAGS according to the result of bitwise OR of two 64-bit opmasks.
  | KORTESTQ = 314
  /// Update EFLAGS according to the result of bitwise OR of two 16-bit opmasks.
  | KORTESTW = 315
  /// Logical OR two 16-bit opmasks.
  | KORW = 316
  /// Shift left 8-bitopmask by specified count.
  | KSHIFTLB = 317
  /// Shift left 32-bitopmask by specified count.
  | KSHIFTLD = 318
  /// Shift left 64-bitopmask by specified count.
  | KSHIFTLQ = 319
  /// Shift left 16-bitopmask by specified count.
  | KSHIFTLW = 320
  /// Shift right 8-bit opmask by specified count.
  | KSHIFTRB = 321
  /// Shift right 32-bit opmask by specified count.
  | KSHIFTRD = 322
  /// Shift right 64-bit opmask by specified count.
  | KSHIFTRQ = 323
  /// Shift right 16-bit opmask by specified count.
  | KSHIFTRW = 324
  /// Update EFLAGS according to result of bitwise TEST of two 8-bit opmasks.
  | KTESTB = 325
  /// Update EFLAGS according to result of bitwise TEST of two 32-bit opmasks.
  | KTESTD = 326
  /// Update EFLAGS according to result of bitwise TEST of two 64-bit opmasks.
  | KTESTQ = 327
  /// Update EFLAGS according to result of bitwise TEST of two 16-bit opmasks.
  | KTESTW = 328
  /// Unpack and interleave two 8-bit opmasks into 16-bit mask.
  | KUNPCKBW = 329
  /// Unpack and interleave two 32-bit opmasks into 64-bit mask.
  | KUNPCKDQ = 330
  /// Unpack and interleave two 16-bit opmasks into 32-bit mask.
  | KUNPCKWD = 331
  /// Bitwise logical XNOR of two 8-bit opmasks.
  | KXNORB = 332
  /// Bitwise logical XNOR of two 32-bit opmasks.
  | KXNORD = 333
  /// Bitwise logical XNOR of two 64-bit opmasks.
  | KXNORQ = 334
  /// Bitwise logical XNOR of two 16-bit opmasks.
  | KXNORW = 335
  /// Logical XOR of two 8-bit opmasks.
  | KXORB = 336
  /// Logical XOR of two 32-bit opmasks.
  | KXORD = 337
  /// Logical XOR of two 64-bit opmasks.
  | KXORQ = 338
  /// Logical XOR of two 16-bit opmasks.
  | KXORW = 339
  /// Load Status Flags into AH Register.
  | LAHF = 340
  /// Load Access Rights Byte.
  | LAR = 341
  /// Load Unaligned Integer 128 Bits.
  | LDDQU = 342
  /// Load MXCSR Register.
  | LDMXCSR = 343
  /// Load Far Pointer (DS).
  | LDS = 344
  /// Load Effective Address.
  | LEA = 345
  /// High Level Procedure Exit.
  | LEAVE = 346
  /// Load Far Pointer (ES).
  | LES = 347
  /// Load Fence.
  | LFENCE = 348
  /// Load Far Pointer (FS).
  | LFS = 349
  /// Load GlobalDescriptor Table Register.
  | LGDT = 350
  /// Load Far Pointer (GS).
  | LGS = 351
  /// Load Interrupt Descriptor Table Register.
  | LIDT = 352
  /// Load Local Descriptor Table Register.
  | LLDT = 353
  /// Load Machine Status Word.
  | LMSW = 354
  /// Assert LOCK# Signal Prefix.
  | LOCK = 355
  /// Load String (byte).
  | LODSB = 356
  /// Load String (doubleword).
  | LODSD = 357
  /// Load String (quadword).
  | LODSQ = 358
  /// Load String (word).
  | LODSW = 359
  /// Loop According to ECX Counter (count <> 0).
  | LOOP = 360
  /// Loop According to ECX Counter (count <> 0 and ZF = 1).
  | LOOPE = 361
  /// Loop According to ECX Counter (count <> 0 and ZF = 0).
  | LOOPNE = 362
  /// Load Segment Limit.
  | LSL = 363
  /// Load Far Pointer (SS).
  | LSS = 364
  /// Load Task Register.
  | LTR = 365
  /// the Number of Leading Zero Bits.
  | LZCNT = 366
  /// Store Selected Bytes of Double Quadword.
  | MASKMOVDQU = 367
  /// Store Selected Bytes of Quadword.
  | MASKMOVQ = 368
  /// Return Maximum Packed Double-Precision Floating-Point Values.
  | MAXPD = 369
  /// Return Maximum Packed Single-Precision Floating-Point Values.
  | MAXPS = 370
  /// Return Maximum Scalar Double-Precision Floating-Point Values.
  | MAXSD = 371
  /// Return Maximum Scalar Single-Precision Floating-Point Values.
  | MAXSS = 372
  /// Memory Fence.
  | MFENCE = 373
  /// Return Minimum Packed Double-Precision Floating-Point Values.
  | MINPD = 374
  /// Return Minimum Packed Single-Precision Floating-Point Values.
  | MINPS = 375
  /// Return Minimum Scalar Double-Precision Floating-Point Values.
  | MINSD = 376
  /// Return Minimum Scalar Single-Precision Floating-Point Values.
  | MINSS = 377
  /// Set Up Monitor Address.
  | MONITOR = 378
  /// MOV.
  | MOV = 379
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | MOVAPD = 380
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | MOVAPS = 381
  /// Move Data After Swapping Bytes.
  | MOVBE = 382
  /// Move Doubleword.
  | MOVD = 383
  /// Move One Double-FP and Duplicate.
  | MOVDDUP = 384
  /// Move Quadword from XMM to MMX Technology Register.
  | MOVDQ2Q = 385
  /// Move Aligned Double Quadword.
  | MOVDQA = 386
  /// Move Unaligned Double Quadword.
  | MOVDQU = 387
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | MOVHLPS = 388
  /// Move High Packed Double-Precision Floating-Point Value.
  | MOVHPD = 389
  /// Move High Packed Single-Precision Floating-Point Values.
  | MOVHPS = 390
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | MOVLHPS = 391
  /// Move Low Packed Double-Precision Floating-Point Value.
  | MOVLPD = 392
  /// Move Low Packed Single-Precision Floating-Point Values.
  | MOVLPS = 393
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | MOVMSKPD = 394
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | MOVMSKPS = 395
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQ = 396
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQA = 397
  /// Store Doubleword Using Non-Temporal Hint.
  | MOVNTI = 398
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPD = 399
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPS = 400
  /// Store of Quadword Using Non-Temporal Hint.
  | MOVNTQ = 401
  /// Move Quadword.
  | MOVQ = 402
  /// Move Quadword from MMX Technology to XMM Register.
  | MOVQ2DQ = 403
  /// Move Data from String to String (byte).
  | MOVSB = 404
  /// Move Data from String to String (doubleword).
  | MOVSD = 405
  /// Move Packed Single-FP High and Duplicate.
  | MOVSHDUP = 406
  /// Move Packed Single-FP Low and Duplicate.
  | MOVSLDUP = 407
  /// Move Data from String to String (quadword).
  | MOVSQ = 408
  /// Move Scalar Single-Precision Floating-Point Values.
  | MOVSS = 409
  /// Move Data from String to String (word).
  | MOVSW = 410
  /// Move with Sign-Extension.
  | MOVSX = 411
  /// Move with Sign-Extension (doubleword to quadword).
  | MOVSXD = 412
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | MOVUPD = 413
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | MOVUPS = 414
  /// Move with Zero-Extend.
  | MOVZX = 415
  /// Compute Multiple Packed Sums of Absolute Difference.
  | MPSADBW = 416
  /// Unsigned Multiply.
  | MUL = 417
  /// Multiply Packed Double-Precision Floating-Point Values.
  | MULPD = 418
  /// Multiply Packed Single-Precision Floating-Point Values.
  | MULPS = 419
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | MULSD = 420
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | MULSS = 421
  /// Unsigned multiply without affecting arithmetic flags.
  | MULX = 422
  /// Monitor Wait.
  | MWAIT = 423
  /// Two's Complement Negation.
  | NEG = 424
  /// No Operation.
  | NOP = 425
  /// One's Complement Negation.
  | NOT = 426
  /// Logical Inclusive OR.
  | OR = 427
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | ORPD = 428
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | ORPS = 429
  /// Output to Port.
  | OUT = 430
  /// Output String to Port.
  | OUTS = 431
  /// Output String to Port (byte).
  | OUTSB = 432
  /// Output String to Port (doubleword).
  | OUTSD = 433
  /// Output String to Port (word).
  | OUTSW = 434
  /// Computes the absolute value of each signed byte data element.
  | PABSB = 435
  /// Computes the absolute value of each signed 32-bit data element.
  | PABSD = 436
  /// Computes the absolute value of each signed 16-bit data element.
  | PABSW = 437
  /// Pack with Signed Saturation.
  | PACKSSDW = 438
  /// Pack with Signed Saturation.
  | PACKSSWB = 439
  /// Pack with Unsigned Saturation.
  | PACKUSDW = 440
  /// Pack with Unsigned Saturation.
  | PACKUSWB = 441
  /// Add Packed byte Integers.
  | PADDB = 442
  /// Add Packed Doubleword Integers.
  | PADDD = 443
  /// Add Packed Quadword Integers.
  | PADDQ = 444
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | PADDSB = 445
  /// Add Packed Signed Integers with Signed Saturation (word).
  | PADDSW = 446
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | PADDUSB = 447
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | PADDUSW = 448
  /// Add Packed word Integers.
  | PADDW = 449
  /// Packed Align Right.
  | PALIGNR = 450
  /// Logical AND.
  | PAND = 451
  /// Logical AND NOT.
  | PANDN = 452
  /// Spin Loop Hint.
  | PAUSE = 453
  /// Average Packed Integers (byte).
  | PAVGB = 454
  /// Average Packed Integers (word).
  | PAVGW = 455
  /// Variable Blend Packed Bytes.
  | PBLENDVB = 456
  /// Blend Packed Words.
  | PBLENDW = 457
  /// Perform carryless multiplication of two 64-bit numbers.
  | PCLMULQDQ = 458
  /// Compare Packed Data for Equal (byte).
  | PCMPEQB = 459
  /// Compare Packed Data for Equal (doubleword).
  | PCMPEQD = 460
  /// Compare Packed Data for Equal (quadword).
  | PCMPEQQ = 461
  /// Compare packed words for equal.
  | PCMPEQW = 462
  /// Packed Compare Explicit Length Strings, Return Index.
  | PCMPESTRI = 463
  /// Packed Compare Explicit Length Strings, Return Mask.
  | PCMPESTRM = 464
  /// Compare Packed Signed Integers for Greater Than (byte).
  | PCMPGTB = 465
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | PCMPGTD = 466
  /// Performs logical compare of greater-than on packed integer quadwords.
  | PCMPGTQ = 467
  /// Compare Packed Signed Integers for Greater Than (word).
  | PCMPGTW = 468
  /// Packed Compare Implicit Length Strings, Return Index.
  | PCMPISTRI = 469
  /// Packed Compare Implicit Length Strings, Return Mask.
  | PCMPISTRM = 470
  /// Parallel deposit of bits using a mask.
  | PDEP = 471
  /// Parallel extraction of bits using a mask.
  | PEXT = 472
  /// Extract Byte.
  | PEXTRB = 473
  /// Extract Dword.
  | PEXTRD = 474
  /// Extract Qword.
  | PEXTRQ = 475
  /// Extract Word.
  | PEXTRW = 476
  /// Packed Horizontal Add.
  | PHADDD = 477
  /// Packed Horizontal Add and Saturate.
  | PHADDSW = 478
  /// Packed Horizontal Add.
  | PHADDW = 479
  /// Packed Horizontal Word Minimum.
  | PHMINPOSUW = 480
  /// Packed Horizontal Subtract.
  | PHSUBD = 481
  /// Packed Horizontal Subtract and Saturate.
  | PHSUBSW = 482
  /// Packed Horizontal Subtract.
  | PHSUBW = 483
  /// Insert Byte.
  | PINSRB = 484
  /// Insert a dword value from 32-bit register or memory into an XMM register.
  | PINSRD = 485
  /// Insert a qword value from 64-bit register or memory into an XMM register.
  | PINSRQ = 486
  /// Insert Word.
  | PINSRW = 487
  /// Multiply and Add Packed Signed and Unsigned Bytes.
  | PMADDUBSW = 488
  /// Multiply and Add Packed Integers.
  | PMADDWD = 489
  /// Compare packed signed byte integers.
  | PMAXSB = 490
  /// Compare packed signed dword integers.
  | PMAXSD = 491
  /// Maximum of Packed Signed Word Integers.
  | PMAXSW = 492
  /// Maximum of Packed Unsigned Byte Integers.
  | PMAXUB = 493
  /// Compare packed unsigned dword integers.
  | PMAXUD = 494
  /// Compare packed unsigned word integers.
  | PMAXUW = 495
  /// Minimum of Packed Signed Byte Integers.
  | PMINSB = 496
  /// Compare packed signed dword integers.
  | PMINSD = 497
  /// Minimum of Packed Signed Word Integers.
  | PMINSW = 498
  /// Minimum of Packed Unsigned Byte Integers.
  | PMINUB = 499
  /// Minimum of Packed Dword Integers.
  | PMINUD = 500
  /// Compare packed unsigned word integers.
  | PMINUW = 501
  /// Move Byte Mask.
  | PMOVMSKB = 502
  /// Packed Move with Sign Extend.
  | PMOVSXBD = 503
  /// Packed Move with Sign Extend.
  | PMOVSXBQ = 504
  /// Packed Move with Sign Extend.
  | PMOVSXBW = 505
  /// Packed Move with Sign Extend.
  | PMOVSXDQ = 506
  /// Packed Move with Sign Extend.
  | PMOVSXWD = 507
  /// Packed Move with Sign Extend.
  | PMOVSXWQ = 508
  /// Packed Move with Zero Extend.
  | PMOVZXBD = 509
  /// Packed Move with Zero Extend.
  | PMOVZXBQ = 510
  /// Packed Move with Zero Extend.
  | PMOVZXBW = 511
  /// Packed Move with Zero Extend.
  | PMOVZXDQ = 512
  /// Packed Move with Zero Extend.
  | PMOVZXWD = 513
  /// Packed Move with Zero Extend.
  | PMOVZXWQ = 514
  /// Multiply Packed Doubleword Integers.
  | PMULDQ = 515
  /// Packed Multiply High with Round and Scale.
  | PMULHRSW = 516
  /// Multiply Packed Unsigned Integers and Store High Result.
  | PMULHUW = 517
  /// Multiply Packed Signed Integers and Store High Result.
  | PMULHW = 518
  /// Multiply Packed Integers and Store Low Result.
  | PMULLD = 519
  /// Multiply Packed Signed Integers and Store Low Result.
  | PMULLW = 520
  /// Multiply Packed Unsigned Doubleword Integers.
  | PMULUDQ = 521
  /// Pop a Value from the Stack.
  | POP = 522
  /// Pop All General-Purpose Registers (word).
  | POPA = 523
  /// Pop All General-Purpose Registers (doubleword).
  | POPAD = 524
  /// Return the Count of Number of Bits Set to 1.
  | POPCNT = 525
  /// Pop Stack into EFLAGS Register (lower 16bits EFLAGS).
  | POPF = 526
  /// Pop Stack into EFLAGS Register (EFLAGS).
  | POPFD = 527
  /// Pop Stack into EFLAGS Register (RFLAGS).
  | POPFQ = 528
  /// Bitwise Logical OR.
  | POR = 529
  /// Prefetch Data Into Caches (using NTA hint).
  | PREFETCHNTA = 530
  /// Prefetch Data Into Caches (using T0 hint).
  | PREFETCHT0 = 531
  /// Prefetch Data Into Caches (using T1 hint).
  | PREFETCHT1 = 532
  /// Prefetch Data Into Caches (using T2 hint).
  | PREFETCHT2 = 533
  /// Prefetch Data into Caches in Anticipation of a Write.
  | PREFETCHW = 534
  /// Prefetch Vector Data Into Caches with Intent to Write and T1 Hint.
  | PREFETCHWT1 = 535
  /// Compute Sum of Absolute Differences.
  | PSADBW = 536
  /// Packed Shuffle Bytes.
  | PSHUFB = 537
  /// Shuffle Packed Doublewords.
  | PSHUFD = 538
  /// Shuffle Packed High Words.
  | PSHUFHW = 539
  /// Shuffle Packed Low Words.
  | PSHUFLW = 540
  /// Shuffle Packed Words.
  | PSHUFW = 541
  /// Packed Sign Byte.
  | PSIGNB = 542
  /// Packed Sign Doubleword.
  | PSIGND = 543
  /// Packed Sign Word.
  | PSIGNW = 544
  /// Shift Packed Data Left Logical (doubleword).
  | PSLLD = 545
  /// Shift Double Quadword Left Logical.
  | PSLLDQ = 546
  /// Shift Packed Data Left Logical (quadword).
  | PSLLQ = 547
  /// Shift Packed Data Left Logical (word).
  | PSLLW = 548
  /// Shift Packed Data Right Arithmetic (doubleword).
  | PSRAD = 549
  /// Shift Packed Data Right Arithmetic (word).
  | PSRAW = 550
  /// Shift Packed Data Right Logical (doubleword).
  | PSRLD = 551
  /// Shift Double Quadword Right Logical.
  | PSRLDQ = 552
  /// Shift Packed Data Right Logical (quadword).
  | PSRLQ = 553
  /// Shift Packed Data Right Logical (word).
  | PSRLW = 554
  /// Subtract Packed Integers (byte).
  | PSUBB = 555
  /// Subtract Packed Integers (doubleword).
  | PSUBD = 556
  /// Subtract Packed Integers (quadword).
  | PSUBQ = 557
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | PSUBSB = 558
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | PSUBSW = 559
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | PSUBUSB = 560
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | PSUBUSW = 561
  /// Subtract Packed Integers (word).
  | PSUBW = 562
  /// Logical Compare.
  | PTEST = 563
  /// Unpack High Data.
  | PUNPCKHBW = 564
  /// Unpack High Data.
  | PUNPCKHDQ = 565
  /// Unpack High Data.
  | PUNPCKHQDQ = 566
  /// Unpack High Data.
  | PUNPCKHWD = 567
  /// Unpack Low Data.
  | PUNPCKLBW = 568
  /// Unpack Low Data.
  | PUNPCKLDQ = 569
  /// Unpack Low Data.
  | PUNPCKLQDQ = 570
  /// Unpack Low Data.
  | PUNPCKLWD = 571
  /// Push Word, Doubleword or Quadword Onto the Stack.
  | PUSH = 572
  /// Push All General-Purpose Registers (word).
  | PUSHA = 573
  /// Push All General-Purpose Registers (doubleword).
  | PUSHAD = 574
  /// Push EFLAGS Register onto the Stack (16bits of EFLAGS).
  | PUSHF = 575
  /// Push EFLAGS Register onto the Stack (EFLAGS).
  | PUSHFD = 576
  /// Push EFLAGS Register onto the Stack (RFLAGS).
  | PUSHFQ = 577
  /// Logical Exclusive OR.
  | PXOR = 578
  /// Rotate x bits (CF, r/m(x)) left once.
  | RCL = 579
  /// Compute reciprocals of packed single-precision floating-point values.
  | RCPPS = 580
  /// Compute reciprocal of scalar single-precision floating-point values.
  | RCPSS = 581
  /// Rotate x bits (CF, r/m(x)) right once.
  | RCR = 582
  /// Read FS Segment Base.
  | RDFSBASE = 583
  /// Read GS Segment Base.
  | RDGSBASE = 584
  /// Read from Model Specific Register.
  | RDMSR = 585
  /// Read Protection Key Rights for User Pages.
  | RDPKRU = 586
  /// Read Performance-Monitoring Counters.
  | RDPMC = 587
  /// Read Random Number.
  | RDRAND = 588
  /// Read Random SEED.
  | RDSEED = 589
  /// Read shadow stack point (SSP).
  | RDSSP = 590
  /// Read Time-Stamp Counter.
  | RDTSC = 591
  /// Read Time-Stamp Counter and Processor ID.
  | RDTSCP = 592
  /// Repeat while ECX not zero.
  | REP = 593
  /// Repeat while equal/Repeat while zero.
  | REPE = 594
  /// Repeat while not equal/Repeat while not zero.
  | REPNE = 595
  /// Repeat while not equal/Repeat while not zero.
  | REPNZ = 596
  /// Repeat while equal/Repeat while zero.
  | REPZ = 597
  /// Far return.
  | RETFar = 598
  /// Far return w/ immediate.
  | RETFarImm = 599
  /// Near return.
  | RETNear = 600
  /// Near return w/ immediate .
  | RETNearImm = 601
  /// Rotate x bits r/m(x) left once.
  | ROL = 602
  /// Rotate x bits r/m(x) right once.
  | ROR = 603
  /// Rotate right without affecting arithmetic flags.
  | RORX = 604
  /// Round Packed Double Precision Floating-Point Values.
  | ROUNDPD = 605
  /// Round Packed Single Precision Floating-Point Values.
  | ROUNDPS = 606
  /// Round Scalar Double Precision Floating-Point Values.
  | ROUNDSD = 607
  /// Round Scalar Single Precision Floating-Point Values.
  | ROUNDSS = 608
  /// Resume from System Management Mode.
  | RSM = 609
  /// Compute reciprocals of square roots of packed single-precision FP values.
  | RSQRTPS = 610
  /// Compute reciprocal of square root of scalar single-precision FP values.
  | RSQRTSS = 611
  /// Restore a shadow stack pointer (SSP).
  | RSTORSSP = 612
  /// Store AH into Flags.
  | SAHF = 613
  /// Shift.
  | SAR = 614
  /// Shift arithmetic right.
  | SARX = 615
  /// Save previous shadow stack pointer (SSP).
  | SAVEPREVSSP = 616
  /// Integer Subtraction with Borrow.
  | SBB = 617
  /// Scan String (byte).
  | SCASB = 618
  /// Scan String (doubleword).
  | SCASD = 619
  /// Scan String (quadword).
  | SCASQ = 620
  /// Scan String (word).
  | SCASW = 621
  /// Set byte if above (CF = 0 and ZF = 0).
  | SETA = 622
  /// Set byte if below (CF = 1).
  | SETB = 623
  /// Set byte if below or equal (CF = 1 or ZF = 1).
  | SETBE = 624
  /// Set byte if greater (ZF = 0 and SF = OF).
  | SETG = 625
  /// Set byte if less (SF <> OF).
  | SETL = 626
  /// Set byte if less or equal (ZF = 1 or SF <> OF).
  | SETLE = 627
  /// Set byte if not below (CF = 0).
  | SETNB = 628
  /// Set byte if not less (SF = OF).
  | SETNL = 629
  /// Set byte if not overflow (OF = 0).
  | SETNO = 630
  /// Set byte if not parity (PF = 0).
  | SETNP = 631
  /// Set byte if not sign (SF = 0).
  | SETNS = 632
  /// Set byte if not zero (ZF = 0).
  | SETNZ = 633
  /// Set byte if overflow (OF = 1).
  | SETO = 634
  /// Set byte if parity (PF = 1).
  | SETP = 635
  /// Set byte if sign (SF = 1).
  | SETS = 636
  /// Set busy bit in a supervisor shadow stack token.
  | SETSSBSY = 637
  /// Set byte if sign (ZF = 1).
  | SETZ = 638
  /// Store Fence.
  | SFENCE = 639
  /// Store Global Descriptor Table Register.
  | SGDT = 640
  /// Perform an Intermediate Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG1 = 641
  /// Perform a Final Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG2 = 642
  /// Calculate SHA1 state E after four rounds.
  | SHA1NEXTE = 643
  /// Perform four rounds of SHA1 operations.
  | SHA1RNDS4 = 644
  /// Perform an intermediate calculation for the next 4 SHA256 message dwords.
  | SHA256MSG1 = 645
  /// Perform the final calculation for the next four SHA256 message dwords.
  | SHA256MSG2 = 646
  /// Perform two rounds of SHA256 operations.
  | SHA256RNDS2 = 647
  /// Shift.
  | SHL = 648
  /// Double Precision Shift Left.
  | SHLD = 649
  /// Shift logic left.
  | SHLX = 650
  /// Shift.
  | SHR = 651
  /// Double Precision Shift Right.
  | SHRD = 652
  /// Shift logic right.
  | SHRX = 653
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | SHUFPD = 654
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | SHUFPS = 655
  /// Store Interrupt Descriptor Table Register.
  | SIDT = 656
  /// Store Local Descriptor Table Register.
  | SLDT = 657
  /// Store Machine Status Word.
  | SMSW = 658
  /// Compute packed square roots of packed double-precision FP values.
  | SQRTPD = 659
  /// Compute square roots of packed single-precision floating-point values.
  | SQRTPS = 660
  /// Compute scalar square root of scalar double-precision FP values.
  | SQRTSD = 661
  /// Compute square root of scalar single-precision floating-point values.
  | SQRTSS = 662
  /// Set AC Flag in EFLAGS Register.
  | STAC = 663
  /// Set Carry Flag.
  | STC = 664
  /// Set Direction Flag.
  | STD = 665
  /// Set Interrupt Flag.
  | STI = 666
  /// Store MXCSR Register State.
  | STMXCSR = 667
  /// Store String (store AL).
  | STOSB = 668
  /// Store String (store EAX).
  | STOSD = 669
  /// Store String (store RAX).
  | STOSQ = 670
  /// Store String (store AX).
  | STOSW = 671
  /// Store Task Register.
  | STR = 672
  /// Subtract.
  | SUB = 673
  /// Subtract Packed Double-Precision Floating-Point Values.
  | SUBPD = 674
  /// Subtract Packed Single-Precision Floating-Point Values.
  | SUBPS = 675
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | SUBSD = 676
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | SUBSS = 677
  /// Swap GS Base Register.
  | SWAPGS = 678
  /// Fast System Call.
  | SYSCALL = 679
  /// Fast System Call.
  | SYSENTER = 680
  /// Fast Return from Fast System Call.
  | SYSEXIT = 681
  /// Return From Fast System Call.
  | SYSRET = 682
  /// Logical Compare.
  | TEST = 683
  /// Count the Number of Trailing Zero Bits.
  | TZCNT = 684
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | UCOMISD = 685
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | UCOMISS = 686
  /// Undefined instruction.
  | UD = 687
  /// Undefined Instruction (Raise invalid opcode exception).
  | UD2 = 688
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | UNPCKHPD = 689
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | UNPCKHPS = 690
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | UNPCKLPD = 691
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | UNPCKLPS = 692
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPD = 693
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPS = 694
  /// Add Scalar Double-Precision Floating-Point Values.
  | VADDSD = 695
  /// Add Scalar Single-Precision Floating-Point Values.
  | VADDSS = 696
  /// Perform dword alignment of two concatenated source vectors.
  | VALIGND = 697
  /// Perform qword alignment of two concatenated source vectors.
  | VALIGNQ = 698
  /// Bitwise Logical AND of Packed Double-Precision Floating-Point Values.
  | VANDNPD = 699
  /// Bitwise Logical AND of Packed Single-Precision Floating-Point Values.
  | VANDNPS = 700
  /// Bitwise Logical AND NOT of Packed Double-Precision Floating-Point Values.
  | VANDPD = 701
  /// Bitwise Logical AND NOT of Packed Single-Precision Floating-Point Values.
  | VANDPS = 702
  /// Replace the VBLENDVPD instructions (using opmask as select control).
  | VBLENDMPD = 703
  /// Replace the VBLENDVPS instructions (using opmask as select control).
  | VBLENDMPS = 704
  /// Broadcast 128 bits of int data in mem to low and high 128-bits in ymm1.
  | VBROADCASTI128 = 705
  /// Broadcast Floating-Point Data.
  | VBROADCASTSS = 706
  /// Compare Scalar Ordered Double-Precision FP Values and Set EFLAGS.
  | VCOMISD = 707
  /// Compare Scalar Ordered Single-Precision FP Values and Set EFLAGS.
  | VCOMISS = 708
  /// Compress packed DP elements of a vector.
  | VCOMPRESSPD = 709
  /// Compress packed SP elements of a vector.
  | VCOMPRESSPS = 710
  /// Convert Packed Double-Precision FP Values to Packed Quadword Integers.
  | VCVTPD2QQ = 711
  /// Convert Packed DP FP Values to Packed Unsigned DWord Integers.
  | VCVTPD2UDQ = 712
  /// Convert Packed DP FP Values to Packed Unsigned QWord Integers.
  | VCVTPD2UQQ = 713
  /// Convert 16-bit FP values to Single-Precision FP values.
  | VCVTPH2PS = 714
  /// Convert Single-Precision FP value to 16-bit FP value.
  | VCVTPS2PH = 715
  /// Convert Packed SP FP Values to Packed Signed QWord Int Values.
  | VCVTPS2QQ = 716
  /// Convert Packed SP FP Values to Packed Unsigned DWord Int Values.
  | VCVTPS2UDQ = 717
  /// Convert Packed SP FP Values to Packed Unsigned QWord Int Values.
  | VCVTPS2UQQ = 718
  /// Convert Packed Quadword Integers to Packed Double-Precision FP Values.
  | VCVTQQ2PD = 719
  /// Convert Packed Quadword Integers to Packed Single-Precision FP Values.
  | VCVTQQ2PS = 720
  /// Convert Scalar Double-Precision FP Value to Integer.
  | VCVTSD2SI = 721
  /// Convert Scalar Double-Precision FP Val to Scalar Single-Precision FP Val.
  | VCVTSD2SS = 722
  /// Convert Scalar Double-Precision FP Value to Unsigned Doubleword Integer.
  | VCVTSD2USI = 723
  /// Convert Dword Integer to Scalar Double-Precision FP Value.
  | VCVTSI2SD = 724
  /// Convert Dword Integer to Scalar Single-Precision FP Value.
  | VCVTSI2SS = 725
  /// Convert Scalar Single-Precision FP Val to Scalar Double-Precision FP Val.
  | VCVTSS2SD = 726
  /// Convert Scalar Single-Precision FP Value to Dword Integer.
  | VCVTSS2SI = 727
  /// Convert Scalar Single-Precision FP Value to Unsigned Doubleword Integer.
  | VCVTSS2USI = 728
  /// Convert with Truncation Packed DP FP Values to Packed QWord Integers.
  | VCVTTPD2QQ = 729
  /// Convert with Truncation Packed DP FP Values to Packed Unsigned DWord Int.
  | VCVTTPD2UDQ = 730
  /// Convert with Truncation Packed DP FP Values to Packed Unsigned QWord Int.
  | VCVTTPD2UQQ = 731
  /// Convert with Truncation Packed SP FP Values to Packed Signed QWord Int.
  | VCVTTPS2QQ = 732
  /// Convert with Truncation Packed SP FP Values to Packed Unsigned DWord Int.
  | VCVTTPS2UDQ = 733
  /// Convert with Truncation Packed SP FP Values to Packed Unsigned QWord Int.
  | VCVTTPS2UQQ = 734
  /// Convert with Truncation Scalar Double-Precision FP Value to Signed.
  | VCVTTSD2SI = 735
  /// Convert with Truncation Scalar DP FP Value to Unsigned Integer.
  | VCVTTSD2USI = 736
  /// Convert with Truncation Scalar Single-Precision FP Value to Dword Integer.
  | VCVTTSS2SI = 737
  /// Convert with Truncation Scalar Single-Precision FP Value to Unsigned Int.
  | VCVTTSS2USI = 738
  /// Convert Packed Unsigned DWord Integers to Packed DP FP Values.
  | VCVTUDQ2PD = 739
  /// Convert Packed Unsigned DWord Integers to Packed SP FP Values.
  | VCVTUDQ2PS = 740
  /// Convert Packed Unsigned QWord Integers to Packed DP FP Values.
  | VCVTUQQ2PD = 741
  /// Convert Packed Unsigned QWord Integers to Packed SP FP Values.
  | VCVTUQQ2PS = 742
  /// Convert an unsigned integer to the low DP FP elem and merge to a vector.
  | VCVTUSI2USD = 743
  /// Convert an unsigned integer to the low SP FP elem and merge to a vector.
  | VCVTUSI2USS = 744
  /// Double Block Packed Sum-Absolute-Differences (SAD) on Unsigned Bytes.
  | VDBPSADBW = 745
  /// Divide Packed Double-Precision Floating-Point Values.
  | VDIVPD = 746
  /// Divide Packed Single-Precision Floating-Point Values.
  | VDIVPS = 747
  /// Divide Scalar Double-Precision Floating-Point Values.
  | VDIVSD = 748
  /// Divide Scalar Single-Precision Floating-Point Values.
  | VDIVSS = 749
  /// Verify a Segment for Reading.
  | VERR = 750
  /// Verify a Segment for Writing.
  | VERW = 751
  /// Compute approximate base-2 exponential of packed DP FP elems of a vector.
  | VEXP2PD = 752
  /// Compute approximate base-2 exponential of packed SP FP elems of a vector.
  | VEXP2PS = 753
  /// Compute approximate base-2 exponential of the low DP FP elem of a vector.
  | VEXP2SD = 754
  /// Compute approximate base-2 exponential of the low SP FP elem of a vector.
  | VEXP2SS = 755
  /// Load Sparse Packed Double-Precision FP Values from Dense Memory.
  | VEXPANDPD = 756
  /// Load Sparse Packed Single-Precision FP Values from Dense Memory.
  | VEXPANDPS = 757
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTF32X4 = 758
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTF64X2 = 759
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTF64X4 = 760
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTI32X4 = 761
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTI64X2 = 762
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTI64X4 = 763
  /// Fix Up Special Packed Float64 Values.
  | VFIXUPIMMPD = 764
  /// Fix Up Special Packed Float32 Values.
  | VFIXUPIMMPS = 765
  /// Fix Up Special Scalar Float64 Value.
  | VFIXUPIMMSD = 766
  /// Fix Up Special Scalar Float32 Value.
  | VFIXUPIMMSS = 767
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD132SD = 768
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD132SS = 769
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD213SD = 770
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD213SS = 771
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD231SD = 772
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD231SS = 773
  /// Tests Types Of a Packed Float64 Values.
  | VFPCLASSPD = 774
  /// Tests Types Of a Packed Float32 Values.
  | VFPCLASSPS = 775
  /// Tests Types Of a Scalar Float64 Values.
  | VFPCLASSSD = 776
  /// Tests Types Of a Scalar Float32 Values.
  | VFPCLASSSS = 777
  /// Convert Exponents of Packed DP FP Values to DP FP Values.
  | VGETEXPPD = 778
  /// Convert Exponents of Packed SP FP Values to SP FP Values.
  | VGETEXPPS = 779
  /// Convert Exponents of Scalar DP FP Values to DP FP Value.
  | VGETEXPSD = 780
  /// Convert Exponents of Scalar SP FP Values to SP FP Value.
  | VGETEXPSS = 781
  /// Extract Float64 Vector of Normalized Mantissas from Float64 Vector.
  | VGETMANTPD = 782
  /// Extract Float32 Vector of Normalized Mantissas from Float32 Vector.
  | VGETMANTPS = 783
  /// Extract Float64 of Normalized Mantissas from Float64 Scalar.
  | VGETMANTSD = 784
  /// Extract Float32 Vector of Normalized Mantissa from Float32 Vector.
  | VGETMANTSS = 785
  /// Insert Packed Floating-Point Values.
  | VINSERTF32X4 = 786
  /// Insert Packed Floating-Point Values.
  | VINSERTF64X2 = 787
  /// Insert Packed Floating-Point Values.
  | VINSERTF64X4 = 788
  /// Insert Packed Integer Values.
  | VINSERTI128 = 789
  /// Insert Packed Floating-Point Values.
  | VINSERTI64X2 = 790
  /// Load Unaligned Integer 128 Bits.
  | VLDDQU = 791
  /// Call to VM Monitor.
  | VMCALL = 792
  /// Clear Virtual-Machine Control Structure.
  | VMCLEAR = 793
  /// Invoke VM function.
  | VMFUNC = 794
  /// Launch Virtual Machine.
  | VMLAUNCH = 795
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | VMOVAPD = 796
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | VMOVAPS = 797
  /// Move Doubleword.
  | VMOVD = 798
  /// Move One Double-FP and Duplicate.
  | VMOVDDUP = 799
  /// Move Aligned Double Quadword.
  | VMOVDQA = 800
  /// Move Aligned Double Quadword.
  | VMOVDQA32 = 801
  /// Move Aligned Double Quadword.
  | VMOVDQA64 = 802
  /// Move Unaligned Double Quadword.
  | VMOVDQU = 803
  /// VMOVDQU with 16-bit granular conditional update.
  | VMOVDQU16 = 804
  /// Move Unaligned Double Quadword.
  | VMOVDQU32 = 805
  /// Move Unaligned Double Quadword.
  | VMOVDQU64 = 806
  /// VMOVDQU with 8-bit granular conditional update.
  | VMOVDQU8 = 807
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | VMOVHLPS = 808
  /// Move High Packed Double-Precision Floating-Point Value.
  | VMOVHPD = 809
  /// Move High Packed Single-Precision Floating-Point Values.
  | VMOVHPS = 810
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | VMOVLHPS = 811
  /// Move Low Packed Double-Precision Floating-Point Value.
  | VMOVLPD = 812
  /// Move Low Packed Single-Precision Floating-Point Values.
  | VMOVLPS = 813
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | VMOVMSKPD = 814
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | VMOVMSKPS = 815
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | VMOVNTDQ = 816
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPD = 817
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPS = 818
  /// Move Quadword.
  | VMOVQ = 819
  /// Move Data from String to String (doubleword).
  | VMOVSD = 820
  /// Move Packed Single-FP High and Duplicate.
  | VMOVSHDUP = 821
  /// Move Packed Single-FP Low and Duplicate.
  | VMOVSLDUP = 822
  /// Move Scalar Single-Precision Floating-Point Values.
  | VMOVSS = 823
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | VMOVUPD = 824
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | VMOVUPS = 825
  /// Load Pointer to Virtual-Machine Control Structure.
  | VMPTRLD = 826
  /// Store Pointer to Virtual-Machine Control Structure.
  | VMPTRST = 827
  /// Reads a component from the VMCS and stores it into a destination operand.
  | VMREAD = 828
  /// Resume Virtual Machine.
  | VMRESUME = 829
  /// Multiply Packed Double-Precision Floating-Point Values.
  | VMULPD = 830
  /// Multiply Packed Single-Precision Floating-Point Values.
  | VMULPS = 831
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | VMULSD = 832
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | VMULSS = 833
  /// Writes a component to the VMCS from a source operand.
  | VMWRITE = 834
  /// Leave VMX Operation.
  | VMXOFF = 835
  /// Enter VMX Operation.
  | VMXON = 836
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | VORPD = 837
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | VORPS = 838
  /// Packed Absolute Value (byte).
  | VPABSB = 839
  /// Packed Absolute Value (dword).
  | VPABSD = 840
  /// Packed Absolute Value (word).
  | VPABSW = 841
  /// Pack with Signed Saturation.
  | VPACKSSDW = 842
  /// Pack with Signed Saturation.
  | VPACKSSWB = 843
  /// Pack with Unsigned Saturation.
  | VPACKUSDW = 844
  /// Pack with Unsigned Saturation.
  | VPACKUSWB = 845
  /// Add Packed byte Integers.
  | VPADDB = 846
  /// Add Packed Doubleword Integers.
  | VPADDD = 847
  /// Add Packed Quadword Integers.
  | VPADDQ = 848
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | VPADDSB = 849
  /// Add Packed Signed Integers with Signed Saturation (word).
  | VPADDSW = 850
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPADDUSB = 851
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | VPADDUSW = 852
  /// Add Packed word Integers.
  | VPADDW = 853
  /// Packed Align Right.
  | VPALIGNR = 854
  /// Logical AND.
  | VPAND = 855
  /// Logical AND NOT.
  | VPANDN = 856
  /// Average Packed Integers (byte).
  | VPAVGB = 857
  /// Average Packed Integers (word).
  | VPAVGW = 858
  /// Blend Byte/Word Vectors Using an Opmask Control.
  | VPBLENDMB = 859
  /// Blend Int32/Int64 Vectors Using an OpMask Control.
  | VPBLENDMD = 860
  /// Blend qword elements using opmask as select control.
  | VPBLENDMQ = 861
  /// Blend word elements using opmask as select control.
  | VPBLENDMW = 862
  /// Broadcast Integer Data.
  | VPBROADCASTB = 863
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTD = 864
  /// Broadcast Mask to Vector Register.
  | VPBROADCASTM = 865
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTQ = 866
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTW = 867
  /// Compare packed signed bytes using specified primitive.
  | VPCMPB = 868
  /// Compare packed signed dwords using specified primitive.
  | VPCMPD = 869
  /// Compare Packed Data for Equal (byte).
  | VPCMPEQB = 870
  /// Compare Packed Data for Equal (doubleword).
  | VPCMPEQD = 871
  /// Compare Packed Data for Equal (quadword).
  | VPCMPEQQ = 872
  /// Compare Packed Data for Equal (word).
  | VPCMPEQW = 873
  /// Packed Compare Explicit Length Strings, Return Index.
  | VPCMPESTRI = 874
  /// Packed Compare Explicit Length Strings, Return Mask.
  | VPCMPESTRM = 875
  /// Compare Packed Signed Integers for Greater Than (byte).
  | VPCMPGTB = 876
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | VPCMPGTD = 877
  /// Compare Packed Data for Greater Than (qword).
  | VPCMPGTQ = 878
  /// Compare Packed Signed Integers for Greater Than (word).
  | VPCMPGTW = 879
  /// Packed Compare Implicit Length Strings, Return Index.
  | VPCMPISTRI = 880
  /// Packed Compare Implicit Length Strings, Return Mask.
  | VPCMPISTRM = 881
  /// Compare packed signed quadwords using specified primitive.
  | VPCMPQ = 882
  /// Compare packed signed words using specified primitive.
  | VPCMPW = 883
  /// Compare packed unsigned bytes using specified primitive.
  | VPCMUB = 884
  /// Compare packed unsigned dwords using specified primitive.
  | VPCMUD = 885
  /// Compare packed unsigned quadwords using specified primitive.
  | VPCMUQ = 886
  /// Compare packed unsigned words using specified primitive.
  | VPCMUW = 887
  /// Store Sparse Packed Doubleword Integer Values into Dense Memory/Register.
  | VPCOMPRESSD = 888
  /// Store Sparse Packed Quadword Integer Values into Dense Memory/Register.
  | VPCOMPRESSQ = 889
  /// Detect conflicts within a vector of packed 32/64-bit integers.
  | VPCONFLICTD = 890
  /// Detect conflicts within a vector of packed 64-bit integers.
  | VPCONFLICTQ = 891
  /// Full Permute of Bytes from Two Tables Overwriting the Index.
  | VPERMI2B = 892
  /// Full permute of two tables of dword elements overwriting the index vector.
  | VPERMI2D = 893
  /// Full permute of two tables of DP elements overwriting the index vector.
  | VPERMI2PD = 894
  /// Full permute of two tables of SP elements overwriting the index vector.
  | VPERMI2PS = 895
  /// Full permute of two tables of qword elements overwriting the index vector.
  | VPERMI2Q = 896
  /// Full Permute From Two Tables Overwriting the Index.
  | VPERMI2W = 897
  /// Full permute of two tables of dword elements overwriting one source table.
  | VPERMT2D = 898
  /// Full permute of two tables of DP elements overwriting one source table.
  | VPERMT2PD = 899
  /// Full permute of two tables of SP elements overwriting one source table.
  | VPERMT2PS = 900
  /// Full permute of two tables of qword elements overwriting one source table.
  | VPERMT2Q = 901
  /// Permute packed word elements.
  | VPERMW = 902
  /// Load Sparse Packed Doubleword Integer Values from Dense Memory / Register.
  | VPEXPANDD = 903
  /// Load Sparse Packed Quadword Integer Values from Dense Memory / Register.
  | VPEXPANDQ = 904
  /// Extract Word.
  | VPEXTRW = 905
  /// Packed Horizontal Add (32-bit).
  | VPHADDD = 906
  /// Packed Horizontal Add and Saturate (16-bit).
  | VPHADDSW = 907
  /// Packed Horizontal Add (16-bit).
  | VPHADDW = 908
  /// Packed Horizontal Word Minimum.
  | VPHMINPOSUW = 909
  /// Packed Horizontal Subtract (32-bit).
  | VPHSUBD = 910
  /// Packed Horizontal Subtract and Saturate (16-bit)
  | VPHSUBSW = 911
  /// Packed Horizontal Subtract (16-bit).
  | VPHSUBW = 912
  /// Insert Byte.
  | VPINSRB = 913
  /// Insert Word.
  | VPINSRW = 914
  /// Count the number of leading zero bits of packed dword elements.
  | VPLZCNTD = 915
  /// Count the number of leading zero bits of packed qword elements.
  | VPLZCNTQ = 916
  /// Multiply and Add Packed Integers.
  | VPMADDWD = 917
  /// Maximum of Packed Signed Integers (byte).
  | VPMAXSB = 918
  /// Maximum of Packed Signed Integers (dword).
  | VPMAXSD = 919
  /// Compute maximum of packed signed 64-bit integer elements.
  | VPMAXSQ = 920
  /// Maximum of Packed Signed Word Integers.
  | VPMAXSW = 921
  /// Maximum of Packed Unsigned Byte Integers.
  | VPMAXUB = 922
  /// Maximum of Packed Unsigned Integers (dword).
  | VPMAXUD = 923
  /// Compute maximum of packed unsigned 64-bit integer elements.
  | VPMAXUQ = 924
  /// Maximum of Packed Unsigned Integers (word).
  | VPMAXUW = 925
  /// Minimum of Packed Signed Integers (byte).
  | VPMINSB = 926
  /// Minimum of Packed Signed Integers (dword).
  | VPMINSD = 927
  /// Compute minimum of packed signed 64-bit integer elements.
  | VPMINSQ = 928
  /// Minimum of Packed Signed Word Integers.
  | VPMINSW = 929
  /// Minimum of Packed Unsigned Byte Integers.
  | VPMINUB = 930
  /// Minimum of Packed Dword Integers.
  | VPMINUD = 931
  /// Compute minimum of packed unsigned 64-bit integer elements.
  | VPMINUQ = 932
  /// Minimum of Packed Unsigned Integers (word).
  | VPMINUW = 933
  /// Convert a vector register in 32/64-bit granularity to an opmask register.
  | VPMOVB2D = 934
  /// Convert a Vector Register to a Mask.
  | VPMOVB2M = 935
  /// Down Convert DWord to Byte.
  | VPMOVDB = 936
  /// Down Convert DWord to Word.
  | VPMOVDW = 937
  /// Convert opmask register to vector register in 8-bit granularity.
  | VPMOVM2B = 938
  /// Convert opmask register to vector register in 32-bit granularity.
  | VPMOVM2D = 939
  /// Convert opmask register to vector register in 64-bit granularity.
  | VPMOVM2Q = 940
  /// Convert opmask register to vector register in 16-bit granularity.
  | VPMOVM2W = 941
  /// Move Byte Mask.
  | VPMOVMSKB = 942
  /// Convert a Vector Register to a Mask.
  | VPMOVQ2M = 943
  /// Down Convert QWord to Byte.
  | VPMOVQB = 944
  /// Down Convert QWord to DWord.
  | VPMOVQD = 945
  /// Down Convert QWord to Word.
  | VPMOVQW = 946
  /// Down Convert DWord to Byte.
  | VPMOVSDB = 947
  /// Down Convert DWord to Word.
  | VPMOVSDW = 948
  /// Down Convert QWord to Byte.
  | VPMOVSQB = 949
  /// Down Convert QWord to Dword.
  | VPMOVSQD = 950
  /// Down Convert QWord to Word.
  | VPMOVSQW = 951
  /// Down Convert Word to Byte.
  | VPMOVSWB = 952
  /// Packed Move with Sign Extend (8-bit to 32-bit).
  | VPMOVSXBD = 953
  /// Packed Move with Sign Extend (8-bit to 64-bit).
  | VPMOVSXBQ = 954
  /// Packed Move with Sign Extend (8-bit to 16-bit).
  | VPMOVSXBW = 955
  /// Packed Move with Sign Extend (32-bit to 64-bit).
  | VPMOVSXDQ = 956
  /// Packed Move with Sign Extend (16-bit to 32-bit).
  | VPMOVSXWD = 957
  /// Packed Move with Sign Extend (16-bit to 64-bit).
  | VPMOVSXWQ = 958
  /// Down Convert DWord to Byte.
  | VPMOVUSDB = 959
  /// Down Convert DWord to Word.
  | VPMOVUSDW = 960
  /// Down Convert QWord to Byte.
  | VPMOVUSQB = 961
  /// Down Convert QWord to DWord
  | VPMOVUSQD = 962
  /// Down Convert QWord to Dword.
  | VPMOVUSQW = 963
  /// Down Convert Word to Byte.
  | VPMOVUSWB = 964
  /// Convert a vector register in 16-bit granularity to an opmask register.
  | VPMOVW2M = 965
  /// Down convert word elements in a vector to byte elements using truncation.
  | VPMOVWB = 966
  /// Packed Move with Zero Extend (8-bit to 32-bit).
  | VPMOVZXBD = 967
  /// Packed Move with Zero Extend (8-bit to 64-bit).
  | VPMOVZXBQ = 968
  /// Packed Move with Zero Extend (8-bit to 16-bit).
  | VPMOVZXBW = 969
  /// Packed Move with Zero Extend (32-bit to 64-bit).
  | VPMOVZXDQ = 970
  /// Packed Move with Zero Extend (16-bit to 32-bit).
  | VPMOVZXWD = 971
  /// Packed Move with Zero Extend (16-bit to 64-bit).
  | VPMOVZXWQ = 972
  /// Multiply Packed Doubleword Integers.
  | VPMULDQ = 973
  /// Packed Multiply High with Round and Scale.
  | VPMULHRSW = 974
  /// Multiply Packed Unsigned Integers and Store High Result.
  | VPMULHUW = 975
  /// Multiply Packed Signed Integers and Store High Result.
  | VPMULHW = 976
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLD = 977
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLQ = 978
  /// Multiply Packed Signed Integers and Store Low Result.
  | VPMULLW = 979
  /// Multiply Packed Unsigned Doubleword Integers.
  | VPMULUDQ = 980
  /// Bitwise Logical OR.
  | VPOR = 981
  /// Rotate dword elem left by a constant shift count with conditional update.
  | VPROLD = 982
  /// Rotate qword elem left by a constant shift count with conditional update.
  | VPROLQ = 983
  /// Rotate dword element left by shift counts specified.
  | VPROLVD = 984
  /// Rotate qword element left by shift counts specified.
  | VPROLVQ = 985
  /// Rotate dword element right by a constant shift count.
  | VPRORD = 986
  /// Rotate qword element right by a constant shift count.
  | VPRORQ = 987
  /// Rotate dword element right by shift counts specified.
  | VPRORRD = 988
  /// Rotate qword element right by shift counts specified.
  | VPRORRQ = 989
  /// Compute Sum of Absolute Differences.
  | VPSADBW = 990
  /// Scatter dword elements in a vector to memory using dword indices.
  | VPSCATTERDD = 991
  /// Scatter qword elements in a vector to memory using dword indices.
  | VPSCATTERDQ = 992
  /// Scatter dword elements in a vector to memory using qword indices.
  | VPSCATTERQD = 993
  /// Scatter qword elements in a vector to memory using qword indices.
  | VPSCATTERQQ = 994
  /// Packed Shuffle Bytes.
  | VPSHUFB = 995
  /// Shuffle Packed Doublewords.
  | VPSHUFD = 996
  /// Shuffle Packed High Words.
  | VPSHUFHW = 997
  /// Shuffle Packed Low Words.
  | VPSHUFLW = 998
  /// Packed SIGN (byte).
  | VPSIGNB = 999
  /// Packed SIGN (doubleword).
  | VPSIGND = 1000
  /// Packed SIGN (word).
  | VPSIGNW = 1001
  /// Shift Packed Data Left Logical (doubleword).
  | VPSLLD = 1002
  /// Shift Double Quadword Left Logical.
  | VPSLLDQ = 1003
  /// Shift Packed Data Left Logical (quadword).
  | VPSLLQ = 1004
  /// Variable Bit Shift Left Logical.
  | VPSLLVW = 1005
  /// Shift Packed Data Left Logical (word).
  | VPSLLW = 1006
  /// Shift Packed Data Right Arithmetic (doubleword).
  | VPSRAD = 1007
  /// Shift qwords right by a constant shift count and shifting in sign bits.
  | VPSRAQ = 1008
  /// Shift qwords right by shift counts in a vector and shifting in sign bits.
  | VPSRAVQ = 1009
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVW = 1010
  /// Shift Packed Data Right Arithmetic (word).
  | VPSRAW = 1011
  /// Shift Packed Data Right Logical (doubleword).
  | VPSRLD = 1012
  /// Shift Double Quadword Right Logical.
  | VPSRLDQ = 1013
  /// Shift Packed Data Right Logical (quadword).
  | VPSRLQ = 1014
  /// Variable Bit Shift Right Logical.
  | VPSRLVW = 1015
  /// Shift Packed Data Right Logical (word).
  | VPSRLW = 1016
  /// Subtract Packed Integers (byte).
  | VPSUBB = 1017
  /// Subtract Packed Integers (doubleword).
  | VPSUBD = 1018
  /// Subtract Packed Integers (quadword).
  | VPSUBQ = 1019
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | VPSUBSB = 1020
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | VPSUBSW = 1021
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPSUBUSB = 1022
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | VPSUBUSW = 1023
  /// Subtract Packed Integers (word).
  | VPSUBW = 1024
  /// Perform bitwise ternary logic operation of three vectors.
  | VPTERLOGD = 1025
  /// Perform bitwise ternary logic operation of three vectors.
  | VPTERLOGQ = 1026
  /// Logical Compare.
  | VPTEST = 1027
  /// Perform bitwise AND of byte elems of two vecs and write results to opmask.
  | VPTESTMB = 1028
  /// Perform bitwise AND of dword elems of 2-vecs and write results to opmask.
  | VPTESTMD = 1029
  /// Perform bitwise AND of qword elems of 2-vecs and write results to opmask.
  | VPTESTMQ = 1030
  /// Perform bitwise AND of word elems of two vecs and write results to opmask.
  | VPTESTMW = 1031
  /// Perform bitwise NAND of byte elems of 2-vecs and write results to opmask.
  | VPTESTNMB = 1032
  /// Perform bitwise NAND of dword elems of 2-vecs and write results to opmask.
  | VPTESTNMD = 1033
  /// Perform bitwise NAND of qword elems of 2-vecs and write results to opmask.
  | VPTESTNMQ = 1034
  /// Perform bitwise NAND of word elems of 2-vecs and write results to opmask.
  | VPTESTNMW = 1035
  /// Unpack High Data.
  | VPUNPCKHBW = 1036
  /// Unpack High Data.
  | VPUNPCKHDQ = 1037
  /// Unpack High Data.
  | VPUNPCKHQDQ = 1038
  /// Unpack High Data.
  | VPUNPCKHWD = 1039
  /// Unpack Low Data.
  | VPUNPCKLBW = 1040
  /// Unpack Low Data.
  | VPUNPCKLDQ = 1041
  /// Unpack Low Data.
  | VPUNPCKLQDQ = 1042
  /// Unpack Low Data.
  | VPUNPCKLWD = 1043
  /// Logical Exclusive OR.
  | VPXOR = 1044
  /// Range Restriction Calculation For Packed Pairs of Float64 Values.
  | VRANGEPD = 1045
  /// Range Restriction Calculation For Packed Pairs of Float32 Values.
  | VRANGEPS = 1046
  /// Range Restriction Calculation From a pair of Scalar Float64 Values.
  | VRANGESD = 1047
  /// Range Restriction Calculation From a Pair of Scalar Float32 Values.
  | VRANGESS = 1048
  /// Compute Approximate Reciprocals of Packed Float64 Values.
  | VRCP14PD = 1049
  /// Compute Approximate Reciprocals of Packed Float32 Values.
  | VRCP14PS = 1050
  /// Compute Approximate Reciprocal of Scalar Float64 Value.
  | VRCP14SD = 1051
  /// Compute Approximate Reciprocal of Scalar Float32 Value.
  | VRCP14SS = 1052
  /// Computes the reciprocal approximation of the float64 values.
  | VRCP28PD = 1053
  /// Computes the reciprocal approximation of the float32 values.
  | VRCP28PS = 1054
  /// Computes the reciprocal approximation of the low float64 value.
  | VRCP28SD = 1055
  /// Computes the reciprocal approximation of the low float32 value.
  | VRCP28SS = 1056
  /// Perform Reduction Transformation on Packed Float64 Values.
  | VREDUCEPD = 1057
  /// Perform Reduction Transformation on Packed Float32 Values.
  | VREDUCEPS = 1058
  /// Perform a Reduction Transformation on a Scalar Float64 Value.
  | VREDUCESD = 1059
  /// Perform a Reduction Transformation on a Scalar Float32 Value.
  | VREDUCESS = 1060
  /// Round Packed Float64 Values To Include A Given Number Of Fraction Bits.
  | VRNDSCALEPD = 1061
  /// Round Packed Float32 Values To Include A Given Number Of Fraction Bits.
  | VRNDSCALEPS = 1062
  /// Round Scalar Float64 Value To Include A Given Number Of Fraction Bits.
  | VRNDSCALESD = 1063
  /// Round Scalar Float32 Value To Include A Given Number Of Fraction Bits.
  | VRNDSCALESS = 1064
  /// Compute Approximate Reciprocals of Square Roots of Packed Float64 Values.
  | VRSQRT14PD = 1065
  /// Compute Approximate Reciprocals of Square Roots of Packed Float32 Values.
  | VRSQRT14PS = 1066
  /// Compute Approximate Reciprocal of Square Root of Scalar Float64 Value.
  | VRSQRT14SD = 1067
  /// Compute Approximate Reciprocal of Square Root of Scalar Float32 Value.
  | VRSQRT14SS = 1068
  /// Computes the reciprocal square root of the float64 values.
  | VRSQRT28PD = 1069
  /// Computes the reciprocal square root of the float32 values.
  | VRSQRT28PS = 1070
  /// Computes the reciprocal square root of the low float64 value.
  | VRSQRT28SD = 1071
  /// Computes the reciprocal square root of the low float32 value.
  | VRSQRT28SS = 1072
  /// Multiply packed DP FP elements of a vector by powers.
  | VSCALEPD = 1073
  /// Multiply packed SP FP elements of a vector by powers.
  | VSCALEPS = 1074
  /// Multiply the low DP FP element of a vector by powers.
  | VSCALESD = 1075
  /// Multiply the low SP FP element of a vector by powers.
  | VSCALESS = 1076
  /// Scatter SP/DP FP elements in a vector to memory using dword indices.
  | VSCATTERDD = 1077
  /// Scatter SP/DP FP elements in a vector to memory using dword indices.
  | VSCATTERDQ = 1078
  /// Scatter SP/DP FP elements in a vector to memory using qword indices.
  | VSCATTERQD = 1079
  /// Scatter SP/DP FP elements in a vector to memory using qword indices.
  | VSCATTERQQ = 1080
  /// Shuffle 128-bit lanes of a vector with 32 bit granular conditional update.
  | VSHUFF32X4 = 1081
  /// Shuffle 128-bit lanes of a vector with 64 bit granular conditional update.
  | VSHUFF64X2 = 1082
  /// Shuffle 128-bit lanes of a vector with 32 bit granular conditional update.
  | VSHUFI32X4 = 1083
  /// Shuffle 128-bit lanes of a vector with 64 bit granular conditional update.
  | VSHUFI64X2 = 1084
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | VSHUFPD = 1085
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | VSHUFPS = 1086
  /// Compute packed square roots of packed double-precision FP values.
  | VSQRTPD = 1087
  /// Compute square roots of packed single-precision floating-point values.
  | VSQRTPS = 1088
  /// Compute scalar square root of scalar double-precision FP values.
  | VSQRTSD = 1089
  /// Compute square root of scalar single-precision floating-point values.
  | VSQRTSS = 1090
  /// Subtract Packed Double-Precision Floating-Point Values.
  | VSUBPD = 1091
  /// Subtract Packed Single-Precision Floating-Point Values.
  | VSUBPS = 1092
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | VSUBSD = 1093
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | VSUBSS = 1094
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | VUCOMISD = 1095
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | VUCOMISS = 1096
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | VUNPCKHPD = 1097
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | VUNPCKHPS = 1098
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | VUNPCKLPD = 1099
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | VUNPCKLPS = 1100
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | VXORPD = 1101
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | VXORPS = 1102
  /// Zero Upper Bits of YMM Registers.
  | VZEROUPPER = 1103
  /// Wait.
  | WAIT = 1104
  /// Write Back and Invalidate Cache.
  | WBINVD = 1105
  /// Write FS Segment Base.
  | WRFSBASE = 1106
  /// Write GS Segment Base.
  | WRGSBASE = 1107
  /// Write to Model Specific Register.
  | WRMSR = 1108
  /// Write Data to User Page Key Register.
  | WRPKRU = 1109
  /// Write to a shadow stack.
  | WRSS = 1110
  /// Write to a user mode shadow stack.
  | WRUSS = 1111
  /// Transactional Abort.
  | XABORT = 1112
  /// Prefix hint to the beginning of an HLE transaction region.
  | XACQUIRE = 1113
  /// Exchange and Add.
  | XADD = 1114
  /// Transactional Begin.
  | XBEGIN = 1115
  /// Exchange Register/Memory with Register.
  | XCHG = 1116
  /// Transactional End.
  | XEND = 1117
  /// Value of Extended Control Register.
  | XGETBV = 1118
  /// Table lookup translation.
  | XLAT = 1119
  /// Table Look-up Translation.
  | XLATB = 1120
  /// Logical Exclusive OR.
  | XOR = 1121
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | XORPD = 1122
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | XORPS = 1123
  /// Prefix hint to the end of an HLE transaction region.
  | XRELEASE = 1124
  /// Restore Processor Extended States.
  | XRSTOR = 1125
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS = 1126
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS64 = 1127
  /// Save Processor Extended States.
  | XSAVE = 1128
  /// Save processor extended states with compaction to memory.
  | XSAVEC = 1129
  /// Save processor extended states with compaction to memory.
  | XSAVEC64 = 1130
  /// Save Processor Extended States Optimized.
  | XSAVEOPT = 1131
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES = 1132
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES64 = 1133
  /// Set Extended Control Register.
  | XSETBV = 1134
  /// Test If In Transactional Execution.
  | XTEST = 1135
  /// Invalid Opcode.
  | InvalOP = 1136

/// We define 8 different RegGrp types. Intel instructions use an integer value
/// such as a REG field of a ModR/M value.
type RegGrp =
  /// AL/AX/EAX/...
  | RG0 = 0
  /// CL/CX/ECX/...
  | RG1 = 1
  /// DL/DX/EDX/...
  | RG2 = 2
  /// BL/BX/EBX/...
  | RG3 = 3
  /// AH/SP/ESP/...
  | RG4 = 4
  /// CH/BP/EBP/...
  | RG5 = 5
  /// DH/SI/ESI/...
  | RG6 = 6
  /// BH/DI/EDI/...
  | RG7 = 7

/// Opcode Group.
type OpGroup =
  | G1 = 0
  | G1Inv64 = 1
  | G1A = 2
  | G2 = 3
  | G3A = 4
  | G3B = 5
  | G4 = 6
  | G5 = 7
  | G6 = 8
  | G7 = 9
  | G8 = 10
  | G9 = 11
  | G10 = 12
  | G11A = 13
  | G11B = 14
  | G12 = 15
  | G13 = 16
  | G14 = 17
  | G15 = 18
  | G16 = 19
  | G17 = 20

/// Specifies the kind of operand. See Appendix A.2 of Volume 2 (Intel Manual)
type OprMode =
  /// Direct address
  | A = 0x1
  /// The VEX.vvvv field of the VEX prefix selects a general purpose register
  | B = 0x2
  /// Bound Register
  | BndR = 0x3
  /// Bound Register or memory
  | BndM = 0x4
  /// The reg field of the ModR/M byte selects a control register
  | C = 0x5
  /// The reg field of the ModR/M byte selects a debug register
  | D = 0x6
  /// General Register or Memory
  | E = 0x7
  /// General Register
  | G = 0x8
  /// The VEX.vvvv field of the VEX prefix selects a 128-bit XMM register or a
  /// 256-bit YMM regerister, determined by operand type
  | H = 0x9
  /// Unsigned Immediate
  | I = 0xa
  /// Signed Immediate
  | SI = 0xb
  /// EIP relative offset
  | J = 0xc
  /// Memory
  | M = 0xd
  /// A ModR/M follows the opcode and specifies the operand. The operand is
  /// either a 128-bit, 256-bit or 512-bit memory location.
  | MZ = 0xe
  /// The R/M field of the ModR/M byte selects a packed-quadword, MMX
  /// technology register
  | N = 0xf
  /// No ModR/M byte. No base register, index register, or scaling factor
  | O = 0x10
  /// The reg field of the ModR/M byte selects a packed quadword MMX technology
  /// register
  | P = 0x11
  /// A ModR/M byte follows the opcode and specifies the operand. The operand
  /// is either an MMX technology register of a memory address
  | Q = 0x12
  /// The R/M field of the ModR/M byte may refer only to a general register
  | R = 0x13
  /// The reg field of the ModR/M byte selects a segment register
  | S = 0x14
  /// The R/M field of the ModR/M byte selects a 128-bit XMM register or a
  /// 256-bit YMM register, determined by operand type
  | U = 0x15
  /// The reg field of the ModR/M byte selects a 128-bit XMM register or a
  /// 256-bit YMM register, determined by operand type
  | V = 0x16
  /// The reg field of the ModR/M byte selects a 128-bit XMM register or a
  /// 256-bit YMM register, 512-bit ZMM register determined by operand type
  | VZ = 0x17
  /// A ModR/M follows the opcode and specifies the operand. The operand is
  /// either a 128-bit XMM register, a 256-bit YMM register, or a memory address
  | W = 0x18
  /// A ModR/M follows the opcode and specifies the operand. The operand is
  /// either a 128-bit XMM register, a 256-bit YMM register, a 512-bit ZMM
  /// register or a memory address
  | WZ = 0x19
  /// Memory addressed by the DS:rSI register pair.
  | X = 0x1a
  /// Memory addressed by the ES:rDI register pair.
  | Y = 0x1b
  /// The reg field of the ModR/M byte is 0b000
  | E0 = 0x1c

/// Specifies the size of operand. See Appendix A.2 of Volume 2
type OprSize =
  /// Word/DWord depending on operand-size attribute
  | A = 0x40
  /// Byte size
  | B = 0x80
  /// 64-bit or 128-bit : Bound Register or Memory
  | Bnd = 0xc0
  /// Doubleword, regardless of operand-size attribute
  | D = 0x100
  /// Register size = Doubledword, Pointer size = Byte
  | DB = 0x140
  /// Double-quadword, regardless of operand-size attribute
  | DQ = 0x180
  /// Register size = Double-quadword, Pointer size = Doubleword
  | DQD = 0x1c0
  /// Register size = Double-quadword, Pointer size depending on operand-size
  /// attribute. If the operand-size is 128-bit, the pointer size is doubleword;
  /// If the operand-size is 256-bit, the pointer size is quadword.
  | DQDQ = 0x200
  /// Register size = Double-quadword, Pointer size = Quadword
  | DQQ = 0x240
  /// Register size = Double-quadword, Pointer size depending on operand-size
  /// attribute. If the operand-size is 128-bit, the pointer size is quadword;
  /// If the operand-size is 256-bit, the pointer size is double-quadword.
  | DQQDQ = 0x280
  /// Register size = Double-quadword, Pointer size = Word
  | DQW = 0x2c0
  /// Register size = Doubledword, Pointer size = Word
  | DW = 0x300
  /// Register size = Double-quadword, Pointer size depending on operand-size
  /// attribute. If the operand-size is 128-bit, the pointer size is word;
  /// If the operand-size is 256-bit, the pointer size is doubleword.
  | DQWD = 0x340
  /// 32-bit, 48 bit, or 80-bit pointer, depending on operand-size attribute
  | P = 0x380
  /// 128-bit or 256-bit packed double-precision floating-point data
  | PD = 0x3c0
  /// Quadword MMX techonolgy register
  | PI = 0x400
  /// 128-bit or 256-bit packed single-precision floating-point data
  | PS = 0x440
  /// 128-bit or 256-bit packed single-precision floating-point data, pointer
  /// size : Quadword
  | PSQ = 0x480
  /// Quadword, regardless of operand-size attribute
  | Q = 0x4c0
  /// Quad-Quadword (256-bits), regardless of operand-size attribute
  | QQ = 0x500
  /// 6-byte or 10-byte pseudo-descriptor
  | S = 0x540
  /// Scalar element of a 128-bit double-precision floating data
  | SD = 0x580
  /// Scalar element of a 128-bit double-precision floating data, but the
  /// pointer size is quadword
  | SDQ = 0x5c0
  /// Scalar element of a 128-bit single-precision floating data
  | SS = 0x600
  /// Scalar element of a 128-bit single-precision floating data, but the
  /// pointer size is doubleword
  | SSD = 0x640
  /// Scalar element of a 128-bit single-precision floating data, but the
  /// pointer size is quadword
  | SSQ = 0x680
  /// Word/DWord/QWord depending on operand-size attribute
  | V = 0x6c0
  /// Word, regardless of operand-size attribute
  | W = 0x700
  /// dq or qq based on the operand-size attribute
  | X = 0x740
  /// 128-bit, 256-bit or 512-bit depending on operand-size attribute
  | XZ = 0x780
  /// Doubleword or quadword (in 64-bit mode), depending on operand-size
  /// attribute
  | Y = 0x7c0
  /// Word for 16-bit operand-size or DWord for 32 or 64-bit operand size
  | Z = 0x800

/// Defines attributes for registers to apply register conversion rules.
type RGrpAttr =
  /// This represents the case where there is no given attribute.
  | ANone = 0x0
  /// Registers defined by the 4th row of Table 2-2. Vol. 2A.
  | AMod11 = 0x1
  /// Registers defined by REG bit of the opcode: some instructions such as PUSH
  /// make use of its opcode to represent the REG bit. REX bits can change the
  /// symbol.
  | ARegInOpREX = 0x2
  /// Registers defined by REG bit of the opcode: some instructions such as PUSH
  /// make use of its opcode to represent the REG bit. REX bits cannot change
  /// the symbol.
  | ARegInOpNoREX = 0x4
  /// Registers defined by REG field of the ModR/M byte.
  | ARegBits = 0x8
  /// Base registers defined by the RM field: first three rows of Table 2-2.
  | ABaseRM = 0x10
  /// Registers defined by the SIB index field.
  | ASIBIdx = 0x20
  /// Registers defined by the SIB base field.
  | ASIBBase = 0x40

/// <summary>
/// Defines four different descriptions of an instruction operand. Most of these
/// descriptions are found in Appendix A. (Opcode Map) of the manual Vol. 2D. We
/// also introduce several new descriptors for our own purpose. <para/>
/// </summary>
type OperandDesc =
  /// The most generic operand kind which can be described with OprMode
  /// and OprSize.
  | ODModeSize of struct (OprMode * OprSize)
  /// This operand is represented as a single register.
  /// (e.g., mov al, 1)
  | ODReg of Register
  /// This operand is represented as a single opcode, and the symbol of the
  /// register symbol must be resolved by looking at the register mapping table
  /// (see GrpEAX for instance).
  | ODRegGrp of RegGrp * OprSize * RGrpAttr
  /// This operand is represented as an immediate value (of one).
  | ODImmOne

/// The scale of Scaled Index.
type Scale =
  /// Times 1
  | X1 = 1
  /// Times 2
  | X2 = 2
  /// Times 4
  | X4 = 4
  /// Times 8
  | X8 = 8

/// Scaled index.
type ScaledIndex = Register * Scale

/// Jump target of a branch instruction.
type JumpTarget =
  | Absolute of Selector * Addr * OperandSize
  | Relative of Offset
and Selector = int16
and Offset = int64
and OperandSize = RegType

/// We define four different types of X86 operands:
/// register, memory, direct address, and immediate.
type Operand =
  | OprReg of Register
  | OprMem of Register option * ScaledIndex option * Disp option * OperandSize
  | OprDirAddr of JumpTarget
  | OprImm of int64
  | Label of string * RegType
/// Displacement.
and Disp = int64

/// A set of operands in an X86 instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand

/// Specific conditions for determining the size of operands.
/// (See Appendix A.2.5 of Vol. 2D).
type SizeCond =
  /// Use 32-bit operands as default in 64-bit mode.
  | SzDef32
  /// Use 64-bit operands as default in 64-bit mode = d64.
  | SzDef64
  /// Use 64-bit operands in 64-bit mode (even with a 66 prefix) = f64.
  | Sz64
  /// Only available when in 64-bit mode = o64.
  | SzOnly64
  /// Invalid or not encodable in 64-bit mode = i64.
  | SzInv64

/// Types of VEX (Vector Extension).
type VEXType =
  /// Original VEX that refers to two-byte opcode map.
  | VEXTwoByteOp = 0x1
  /// Original VEX that refers to three-byte opcode map #1.
  | VEXThreeByteOpOne = 0x2
  /// Original VEX that refers to three-byte opcode map #2.
  | VEXThreeByteOpTwo = 0x4
  /// EVEX Mask
  | EVEX = 0x10
  /// Enhanced VEX that refers to two-byte opcode map.
  | EVEXTwoByteOp = 0x11
  /// Original VEX that refers to three-byte opcode map #1.
  | EVEXThreeByteOpOne = 0x12
  /// Original VEX that refers to three-byte opcode map #2.
  | EVEXThreeByteOpTwo = 0x14

module internal VEXType = begin
  let isOriginal (vt: VEXType) = int vt &&& 0x10 = 0
  let isEnhanced (vt: VEXType) = int vt &&& 0x10 <> 0
  let isTwoByteOp (vt: VEXType) = int vt &&& 0x1 <> 0
  let isThreeByteOpOne (vt: VEXType) = int vt &&& 0x2 <> 0
  let isThreeByteOpTwo (vt: VEXType) = int vt &&& 0x4 <> 0
end

/// Represents the size information of an instruction.
type InsSize = {
  MemSize       : MemorySize
  RegSize       : RegType
  OperationSize : RegType
  SizeCond      : SizeCond
}
and MemorySize = {
  EffOprSize      : RegType
  EffAddrSize     : RegType
  EffRegSize      : RegType
}

/// Intel's memory operand is represented by two tables (ModR/M and SIB table).
/// Some memory operands do need SIB table lookups, whereas some memory operands
/// only need to look up the ModR/M table.
type internal MemLookupType =
  | SIB (* Need SIB lookup *)
  | NOSIB of RegGrp option (* No need *)

/// Vector destination merging/zeroing: P[23] encodes the destination result
/// behavior which either zeroes the masked elements or leave masked element
/// unchanged.
type ZeroingOrMerging =
  | Zeroing
  | Merging

type EVEXPrefix = {
  Z   : ZeroingOrMerging
  AAA : uint8 (* Embedded opmask register specifier *)
}

/// Information about Intel vector extension.
type VEXInfo = {
  VVVV            : byte
  VectorLength    : RegType
  VEXType         : VEXType
  VPrefixes       : Prefix
  VREXPrefix      : REXPrefix
  EVEXPrx         : EVEXPrefix option
}

/// Temporary information needed for parsing the opcode and the operands. This
/// includes prefixes, rexprefix, VEX information, and the word size.
type internal TemporaryInfo = {
  /// Prefixes.
  TPrefixes        : Prefix
  /// REX prefixes.
  TREXPrefix       : REXPrefix
  /// VEX information.
  TVEXInfo         : VEXInfo option
  /// Current architecture word size.
  TWordSize        : WordSize
}

/// Basic information obtained by parsing an Intel instruction.
[<NoComparison; CustomEquality>]
type InsInfo = {
  /// Prefixes.
  Prefixes        : Prefix
  /// REX Prefix.
  REXPrefix       : REXPrefix
  /// VEX information.
  VEXInfo         : VEXInfo option
  /// Opcode.
  Opcode          : Opcode
  /// Operands.
  Operands        : Operands
  /// Instruction size information.
  InsSize         : InsSize
}
with
  override __.GetHashCode () =
    hash (__.Prefixes,
          __.REXPrefix,
          __.VEXInfo,
          __.Opcode,
          __.Operands,
          __.InsSize)
  override __.Equals (i) =
    match i with
    | :? InsInfo as i ->
      i.Prefixes = __.Prefixes
      && i.REXPrefix = __.REXPrefix
      && i.VEXInfo = __.VEXInfo
      && i.Opcode = __.Opcode
      && i.Operands = __.Operands
      && i.InsSize = __.InsSize
    | _ -> false

// vim: set tw=80 sts=2 sw=2:
