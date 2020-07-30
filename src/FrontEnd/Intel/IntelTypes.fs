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
  /// Bound prefix is encoded using F2H if the following conditions are true.
  | PrxBND = 0x4
  /// REP or REPE/REPZ is encoded using F3H.
  | PrxREPZ = 0x8
  | PrxCS = 0x10         (* Group 2 *)
  | PrxSS = 0x20
  | PrxDS = 0x40
  | PrxES = 0x80
  | PrxFS = 0x100
  | PrxGS = 0x200
  /// Operand-size override prefix is encoded using 66H.
  | PrxOPSIZE = 0x400   (* Group 3 *)
  /// 67H - Address-size override prefix.
  | PrxADDRSIZE = 0x800 (* Group 4 *)

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
  | INCSSPD = 250
  /// Increment the shadow stack pointer (SSP).
  | INCSSPQ = 251
  /// Input from Port to String.
  | INS = 252
  /// Input from Port to String (byte).
  | INSB = 253
  /// Input from Port to String (doubleword).
  | INSD = 254
  /// Insert Scalar Single-Precision Floating-Point Value.
  | INSERTPS = 255
  /// Input from Port to String (word).
  | INSW = 256
  /// Call to Interrupt (Interrupt vector specified by immediate byte).
  | INT = 257
  /// Call to Interrupt (Interrupt 3?trap to debugger).
  | INT3 = 258
  /// Call to Interrupt (InteInterrupt 4?if overflow flag is 1).
  | INTO = 259
  /// Invalidate Internal Caches.
  | INVD = 260
  /// Invalidate Translations Derived from EPT.
  | INVEPT = 261
  /// Invalidate TLB Entries.
  | INVLPG = 262
  /// Invalidate Process-Context Identifier.
  | INVPCID = 263
  /// Invalidate Translations Based on VPID.
  | INVVPID = 264
  /// Return from interrupt.
  | IRET = 265
  /// Interrupt return (32-bit operand size).
  | IRETD = 266
  /// Interrupt return (64-bit operand size).
  | IRETQ = 267
  /// Interrupt return (16-bit operand size).
  | IRETW = 268
  /// Jump if Condition Is Met (Jump short if above, CF = 0 and ZF = 0).
  | JNBE = 269
  | JA = 269
  /// Jump if Condition Is Met (Jump short if below, CF = 1).
  | JC = 270
  | JNAE = 270
  | JB = 270
  /// Jump if Condition Is Met (Jump short if below or equal, CF = 1 or ZF).
  | JNA = 271
  | JBE = 271
  /// Jump if Condition Is Met (Jump short if CX register is 0).
  | JCXZ = 272
  /// Jump if Condition Is Met (Jump short if ECX register is 0).
  | JECXZ = 273
  /// Jump if Condition Is Met (Jump short if RCX register is 0).
  | JRCXZ = 274
  /// Jump if Condition Is Met (Jump short if greater, ZF = 0 and SF = OF).
  | JNLE = 275
  | JG = 275
  /// Jump if Condition Is Met (Jump short if less, SF <> OF).
  | JNGE = 276
  | JL = 276
  /// Jump if Cond Is Met (Jump short if less or equal, ZF = 1 or SF <> OF).
  | JNG = 277
  | JLE = 277
  /// Far jmp.
  | JMPFar = 278
  /// Near jmp.
  | JMPNear = 279
  /// Jump if Condition Is Met (Jump near if not below, CF = 0).
  | JAE = 280
  | JNC = 280
  | JNB = 280
  /// Jump if Condition Is Met (Jump near if not less, SF = OF).
  | JGE = 281
  | JNL = 281
  /// Jump if Condition Is Met (Jump near if not overflow, OF = 0).
  | JNO = 282
  /// Jump if Condition Is Met (Jump near if not parity, PF = 0).
  | JPO = 283
  | JNP = 283
  /// Jump if Condition Is Met (Jump near if not sign, SF = 0).
  | JNS = 284
  /// Jump if Condition Is Met (Jump near if not zero, ZF = 0).
  | JNZ = 285
  | JNE = 285
  /// Jump if Condition Is Met (Jump near if overflow, OF = 1).
  | JO = 286
  /// Jump if Condition Is Met (Jump near if parity, PF = 1).
  | JP = 287
  | JPE = 287
  /// Jump if Condition Is Met (Jump short if sign, SF = 1).
  | JS = 288
  /// Jump if Condition Is Met (Jump short if zero, ZF = 1).
  | JZ = 289
  | JE = 289
  /// Add two 8-bit opmasks.
  | KADDB = 290
  /// Add two 32-bit opmasks.
  | KADDD = 291
  /// Add two 64-bit opmasks.
  | KADDQ = 292
  /// Add two 16-bit opmasks.
  | KADDW = 293
  /// Logical AND two 8-bit opmasks.
  | KANDB = 294
  /// Logical AND two 32-bit opmasks.
  | KANDD = 295
  /// Logical AND NOT two 8-bit opmasks.
  | KANDNB = 296
  /// Logical AND NOT two 32-bit opmasks.
  | KANDND = 297
  /// Logical AND NOT two 64-bit opmasks.
  | KANDNQ = 298
  /// Logical AND NOT two 16-bit opmasks.
  | KANDNW = 299
  /// Logical AND two 64-bit opmasks.
  | KANDQ = 300
  /// Logical AND two 16-bit opmasks.
  | KANDW = 301
  /// Move from or move to opmask register of 8-bit data.
  | KMOVB = 302
  /// Move from or move to opmask register of 32-bit data.
  | KMOVD = 303
  /// Move from or move to opmask register of 64-bit data.
  | KMOVQ = 304
  /// Move from or move to opmask register of 16-bit data.
  | KMOVW = 305
  /// Bitwise NOT of two 8-bit opmasks.
  | KNOTB = 306
  /// Bitwise NOT of two 32-bit opmasks.
  | KNOTD = 307
  /// Bitwise NOT of two 64-bit opmasks.
  | KNOTQ = 308
  /// Bitwise NOT of two 16-bit opmasks.
  | KNOTW = 309
  /// Logical OR two 8-bit opmasks.
  | KORB = 310
  /// Logical OR two 32-bit opmasks.
  | KORD = 311
  /// Logical OR two 64-bit opmasks.
  | KORQ = 312
  /// Update EFLAGS according to the result of bitwise OR of two 8-bit opmasks.
  | KORTESTB = 313
  /// Update EFLAGS according to the result of bitwise OR of two 32-bit opmasks.
  | KORTESTD = 314
  /// Update EFLAGS according to the result of bitwise OR of two 64-bit opmasks.
  | KORTESTQ = 315
  /// Update EFLAGS according to the result of bitwise OR of two 16-bit opmasks.
  | KORTESTW = 316
  /// Logical OR two 16-bit opmasks.
  | KORW = 317
  /// Shift left 8-bitopmask by specified count.
  | KSHIFTLB = 318
  /// Shift left 32-bitopmask by specified count.
  | KSHIFTLD = 319
  /// Shift left 64-bitopmask by specified count.
  | KSHIFTLQ = 320
  /// Shift left 16-bitopmask by specified count.
  | KSHIFTLW = 321
  /// Shift right 8-bit opmask by specified count.
  | KSHIFTRB = 322
  /// Shift right 32-bit opmask by specified count.
  | KSHIFTRD = 323
  /// Shift right 64-bit opmask by specified count.
  | KSHIFTRQ = 324
  /// Shift right 16-bit opmask by specified count.
  | KSHIFTRW = 325
  /// Update EFLAGS according to result of bitwise TEST of two 8-bit opmasks.
  | KTESTB = 326
  /// Update EFLAGS according to result of bitwise TEST of two 32-bit opmasks.
  | KTESTD = 327
  /// Update EFLAGS according to result of bitwise TEST of two 64-bit opmasks.
  | KTESTQ = 328
  /// Update EFLAGS according to result of bitwise TEST of two 16-bit opmasks.
  | KTESTW = 329
  /// Unpack and interleave two 8-bit opmasks into 16-bit mask.
  | KUNPCKBW = 330
  /// Unpack and interleave two 32-bit opmasks into 64-bit mask.
  | KUNPCKDQ = 331
  /// Unpack and interleave two 16-bit opmasks into 32-bit mask.
  | KUNPCKWD = 332
  /// Bitwise logical XNOR of two 8-bit opmasks.
  | KXNORB = 333
  /// Bitwise logical XNOR of two 32-bit opmasks.
  | KXNORD = 334
  /// Bitwise logical XNOR of two 64-bit opmasks.
  | KXNORQ = 335
  /// Bitwise logical XNOR of two 16-bit opmasks.
  | KXNORW = 336
  /// Logical XOR of two 8-bit opmasks.
  | KXORB = 337
  /// Logical XOR of two 32-bit opmasks.
  | KXORD = 338
  /// Logical XOR of two 64-bit opmasks.
  | KXORQ = 339
  /// Logical XOR of two 16-bit opmasks.
  | KXORW = 340
  /// Load Status Flags into AH Register.
  | LAHF = 341
  /// Load Access Rights Byte.
  | LAR = 342
  /// Load Unaligned Integer 128 Bits.
  | LDDQU = 343
  /// Load MXCSR Register.
  | LDMXCSR = 344
  /// Load Far Pointer (DS).
  | LDS = 345
  /// Load Effective Address.
  | LEA = 346
  /// High Level Procedure Exit.
  | LEAVE = 347
  /// Load Far Pointer (ES).
  | LES = 348
  /// Load Fence.
  | LFENCE = 349
  /// Load Far Pointer (FS).
  | LFS = 350
  /// Load GlobalDescriptor Table Register.
  | LGDT = 351
  /// Load Far Pointer (GS).
  | LGS = 352
  /// Load Interrupt Descriptor Table Register.
  | LIDT = 353
  /// Load Local Descriptor Table Register.
  | LLDT = 354
  /// Load Machine Status Word.
  | LMSW = 355
  /// Assert LOCK# Signal Prefix.
  | LOCK = 356
  /// Load String (byte).
  | LODSB = 357
  /// Load String (doubleword).
  | LODSD = 358
  /// Load String (quadword).
  | LODSQ = 359
  /// Load String (word).
  | LODSW = 360
  /// Loop According to ECX Counter (count <> 0).
  | LOOP = 361
  /// Loop According to ECX Counter (count <> 0 and ZF = 1).
  | LOOPE = 362
  /// Loop According to ECX Counter (count <> 0 and ZF = 0).
  | LOOPNE = 363
  /// Load Segment Limit.
  | LSL = 364
  /// Load Far Pointer (SS).
  | LSS = 365
  /// Load Task Register.
  | LTR = 366
  /// the Number of Leading Zero Bits.
  | LZCNT = 367
  /// Store Selected Bytes of Double Quadword.
  | MASKMOVDQU = 368
  /// Store Selected Bytes of Quadword.
  | MASKMOVQ = 369
  /// Return Maximum Packed Double-Precision Floating-Point Values.
  | MAXPD = 370
  /// Return Maximum Packed Single-Precision Floating-Point Values.
  | MAXPS = 371
  /// Return Maximum Scalar Double-Precision Floating-Point Values.
  | MAXSD = 372
  /// Return Maximum Scalar Single-Precision Floating-Point Values.
  | MAXSS = 373
  /// Memory Fence.
  | MFENCE = 374
  /// Return Minimum Packed Double-Precision Floating-Point Values.
  | MINPD = 375
  /// Return Minimum Packed Single-Precision Floating-Point Values.
  | MINPS = 376
  /// Return Minimum Scalar Double-Precision Floating-Point Values.
  | MINSD = 377
  /// Return Minimum Scalar Single-Precision Floating-Point Values.
  | MINSS = 378
  /// Set Up Monitor Address.
  | MONITOR = 379
  /// MOV.
  | MOV = 380
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | MOVAPD = 381
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | MOVAPS = 382
  /// Move Data After Swapping Bytes.
  | MOVBE = 383
  /// Move Doubleword.
  | MOVD = 384
  /// Move One Double-FP and Duplicate.
  | MOVDDUP = 385
  /// Move Quadword from XMM to MMX Technology Register.
  | MOVDQ2Q = 386
  /// Move Aligned Double Quadword.
  | MOVDQA = 387
  /// Move Unaligned Double Quadword.
  | MOVDQU = 388
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | MOVHLPS = 389
  /// Move High Packed Double-Precision Floating-Point Value.
  | MOVHPD = 390
  /// Move High Packed Single-Precision Floating-Point Values.
  | MOVHPS = 391
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | MOVLHPS = 392
  /// Move Low Packed Double-Precision Floating-Point Value.
  | MOVLPD = 393
  /// Move Low Packed Single-Precision Floating-Point Values.
  | MOVLPS = 394
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | MOVMSKPD = 395
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | MOVMSKPS = 396
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQ = 397
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQA = 398
  /// Store Doubleword Using Non-Temporal Hint.
  | MOVNTI = 399
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPD = 400
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPS = 401
  /// Store of Quadword Using Non-Temporal Hint.
  | MOVNTQ = 402
  /// Move Quadword.
  | MOVQ = 403
  /// Move Quadword from MMX Technology to XMM Register.
  | MOVQ2DQ = 404
  /// Move Data from String to String (byte).
  | MOVSB = 405
  /// Move Data from String to String (doubleword).
  | MOVSD = 406
  /// Move Packed Single-FP High and Duplicate.
  | MOVSHDUP = 407
  /// Move Packed Single-FP Low and Duplicate.
  | MOVSLDUP = 408
  /// Move Data from String to String (quadword).
  | MOVSQ = 409
  /// Move Scalar Single-Precision Floating-Point Values.
  | MOVSS = 410
  /// Move Data from String to String (word).
  | MOVSW = 411
  /// Move with Sign-Extension.
  | MOVSX = 412
  /// Move with Sign-Extension (doubleword to quadword).
  | MOVSXD = 413
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | MOVUPD = 414
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | MOVUPS = 415
  /// Move with Zero-Extend.
  | MOVZX = 416
  /// Compute Multiple Packed Sums of Absolute Difference.
  | MPSADBW = 417
  /// Unsigned Multiply.
  | MUL = 418
  /// Multiply Packed Double-Precision Floating-Point Values.
  | MULPD = 419
  /// Multiply Packed Single-Precision Floating-Point Values.
  | MULPS = 420
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | MULSD = 421
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | MULSS = 422
  /// Unsigned multiply without affecting arithmetic flags.
  | MULX = 423
  /// Monitor Wait.
  | MWAIT = 424
  /// Two's Complement Negation.
  | NEG = 425
  /// No Operation.
  | NOP = 426
  /// One's Complement Negation.
  | NOT = 427
  /// Logical Inclusive OR.
  | OR = 428
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | ORPD = 429
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | ORPS = 430
  /// Output to Port.
  | OUT = 431
  /// Output String to Port.
  | OUTS = 432
  /// Output String to Port (byte).
  | OUTSB = 433
  /// Output String to Port (doubleword).
  | OUTSD = 434
  /// Output String to Port (word).
  | OUTSW = 435
  /// Computes the absolute value of each signed byte data element.
  | PABSB = 436
  /// Computes the absolute value of each signed 32-bit data element.
  | PABSD = 437
  /// Computes the absolute value of each signed 16-bit data element.
  | PABSW = 438
  /// Pack with Signed Saturation.
  | PACKSSDW = 439
  /// Pack with Signed Saturation.
  | PACKSSWB = 440
  /// Pack with Unsigned Saturation.
  | PACKUSDW = 441
  /// Pack with Unsigned Saturation.
  | PACKUSWB = 442
  /// Add Packed byte Integers.
  | PADDB = 443
  /// Add Packed Doubleword Integers.
  | PADDD = 444
  /// Add Packed Quadword Integers.
  | PADDQ = 445
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | PADDSB = 446
  /// Add Packed Signed Integers with Signed Saturation (word).
  | PADDSW = 447
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | PADDUSB = 448
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | PADDUSW = 449
  /// Add Packed word Integers.
  | PADDW = 450
  /// Packed Align Right.
  | PALIGNR = 451
  /// Logical AND.
  | PAND = 452
  /// Logical AND NOT.
  | PANDN = 453
  /// Spin Loop Hint.
  | PAUSE = 454
  /// Average Packed Integers (byte).
  | PAVGB = 455
  /// Average Packed Integers (word).
  | PAVGW = 456
  /// Variable Blend Packed Bytes.
  | PBLENDVB = 457
  /// Blend Packed Words.
  | PBLENDW = 458
  /// Perform carryless multiplication of two 64-bit numbers.
  | PCLMULQDQ = 459
  /// Compare Packed Data for Equal (byte).
  | PCMPEQB = 460
  /// Compare Packed Data for Equal (doubleword).
  | PCMPEQD = 461
  /// Compare Packed Data for Equal (quadword).
  | PCMPEQQ = 462
  /// Compare packed words for equal.
  | PCMPEQW = 463
  /// Packed Compare Explicit Length Strings, Return Index.
  | PCMPESTRI = 464
  /// Packed Compare Explicit Length Strings, Return Mask.
  | PCMPESTRM = 465
  /// Compare Packed Signed Integers for Greater Than (byte).
  | PCMPGTB = 466
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | PCMPGTD = 467
  /// Performs logical compare of greater-than on packed integer quadwords.
  | PCMPGTQ = 468
  /// Compare Packed Signed Integers for Greater Than (word).
  | PCMPGTW = 469
  /// Packed Compare Implicit Length Strings, Return Index.
  | PCMPISTRI = 470
  /// Packed Compare Implicit Length Strings, Return Mask.
  | PCMPISTRM = 471
  /// Parallel deposit of bits using a mask.
  | PDEP = 472
  /// Parallel extraction of bits using a mask.
  | PEXT = 473
  /// Extract Byte.
  | PEXTRB = 474
  /// Extract Dword.
  | PEXTRD = 475
  /// Extract Qword.
  | PEXTRQ = 476
  /// Extract Word.
  | PEXTRW = 477
  /// Packed Horizontal Add.
  | PHADDD = 478
  /// Packed Horizontal Add and Saturate.
  | PHADDSW = 479
  /// Packed Horizontal Add.
  | PHADDW = 480
  /// Packed Horizontal Word Minimum.
  | PHMINPOSUW = 481
  /// Packed Horizontal Subtract.
  | PHSUBD = 482
  /// Packed Horizontal Subtract and Saturate.
  | PHSUBSW = 483
  /// Packed Horizontal Subtract.
  | PHSUBW = 484
  /// Insert Byte.
  | PINSRB = 485
  /// Insert a dword value from 32-bit register or memory into an XMM register.
  | PINSRD = 486
  /// Insert a qword value from 64-bit register or memory into an XMM register.
  | PINSRQ = 487
  /// Insert Word.
  | PINSRW = 488
  /// Multiply and Add Packed Signed and Unsigned Bytes.
  | PMADDUBSW = 489
  /// Multiply and Add Packed Integers.
  | PMADDWD = 490
  /// Compare packed signed byte integers.
  | PMAXSB = 491
  /// Compare packed signed dword integers.
  | PMAXSD = 492
  /// Maximum of Packed Signed Word Integers.
  | PMAXSW = 493
  /// Maximum of Packed Unsigned Byte Integers.
  | PMAXUB = 494
  /// Compare packed unsigned dword integers.
  | PMAXUD = 495
  /// Compare packed unsigned word integers.
  | PMAXUW = 496
  /// Minimum of Packed Signed Byte Integers.
  | PMINSB = 497
  /// Compare packed signed dword integers.
  | PMINSD = 498
  /// Minimum of Packed Signed Word Integers.
  | PMINSW = 499
  /// Minimum of Packed Unsigned Byte Integers.
  | PMINUB = 500
  /// Minimum of Packed Dword Integers.
  | PMINUD = 501
  /// Compare packed unsigned word integers.
  | PMINUW = 502
  /// Move Byte Mask.
  | PMOVMSKB = 503
  /// Packed Move with Sign Extend.
  | PMOVSXBD = 504
  /// Packed Move with Sign Extend.
  | PMOVSXBQ = 505
  /// Packed Move with Sign Extend.
  | PMOVSXBW = 506
  /// Packed Move with Sign Extend.
  | PMOVSXDQ = 507
  /// Packed Move with Sign Extend.
  | PMOVSXWD = 508
  /// Packed Move with Sign Extend.
  | PMOVSXWQ = 509
  /// Packed Move with Zero Extend.
  | PMOVZXBD = 510
  /// Packed Move with Zero Extend.
  | PMOVZXBQ = 511
  /// Packed Move with Zero Extend.
  | PMOVZXBW = 512
  /// Packed Move with Zero Extend.
  | PMOVZXDQ = 513
  /// Packed Move with Zero Extend.
  | PMOVZXWD = 514
  /// Packed Move with Zero Extend.
  | PMOVZXWQ = 515
  /// Multiply Packed Doubleword Integers.
  | PMULDQ = 516
  /// Packed Multiply High with Round and Scale.
  | PMULHRSW = 517
  /// Multiply Packed Unsigned Integers and Store High Result.
  | PMULHUW = 518
  /// Multiply Packed Signed Integers and Store High Result.
  | PMULHW = 519
  /// Multiply Packed Integers and Store Low Result.
  | PMULLD = 520
  /// Multiply Packed Signed Integers and Store Low Result.
  | PMULLW = 521
  /// Multiply Packed Unsigned Doubleword Integers.
  | PMULUDQ = 522
  /// Pop a Value from the Stack.
  | POP = 523
  /// Pop All General-Purpose Registers (word).
  | POPA = 524
  /// Pop All General-Purpose Registers (doubleword).
  | POPAD = 525
  /// Return the Count of Number of Bits Set to 1.
  | POPCNT = 526
  /// Pop Stack into EFLAGS Register (lower 16bits EFLAGS).
  | POPF = 527
  /// Pop Stack into EFLAGS Register (EFLAGS).
  | POPFD = 528
  /// Pop Stack into EFLAGS Register (RFLAGS).
  | POPFQ = 529
  /// Bitwise Logical OR.
  | POR = 530
  /// Prefetch Data Into Caches (using NTA hint).
  | PREFETCHNTA = 531
  /// Prefetch Data Into Caches (using T0 hint).
  | PREFETCHT0 = 532
  /// Prefetch Data Into Caches (using T1 hint).
  | PREFETCHT1 = 533
  /// Prefetch Data Into Caches (using T2 hint).
  | PREFETCHT2 = 534
  /// Prefetch Data into Caches in Anticipation of a Write.
  | PREFETCHW = 535
  /// Prefetch Vector Data Into Caches with Intent to Write and T1 Hint.
  | PREFETCHWT1 = 536
  /// Compute Sum of Absolute Differences.
  | PSADBW = 537
  /// Packed Shuffle Bytes.
  | PSHUFB = 538
  /// Shuffle Packed Doublewords.
  | PSHUFD = 539
  /// Shuffle Packed High Words.
  | PSHUFHW = 540
  /// Shuffle Packed Low Words.
  | PSHUFLW = 541
  /// Shuffle Packed Words.
  | PSHUFW = 542
  /// Packed Sign Byte.
  | PSIGNB = 543
  /// Packed Sign Doubleword.
  | PSIGND = 544
  /// Packed Sign Word.
  | PSIGNW = 545
  /// Shift Packed Data Left Logical (doubleword).
  | PSLLD = 546
  /// Shift Double Quadword Left Logical.
  | PSLLDQ = 547
  /// Shift Packed Data Left Logical (quadword).
  | PSLLQ = 548
  /// Shift Packed Data Left Logical (word).
  | PSLLW = 549
  /// Shift Packed Data Right Arithmetic (doubleword).
  | PSRAD = 550
  /// Shift Packed Data Right Arithmetic (word).
  | PSRAW = 551
  /// Shift Packed Data Right Logical (doubleword).
  | PSRLD = 552
  /// Shift Double Quadword Right Logical.
  | PSRLDQ = 553
  /// Shift Packed Data Right Logical (quadword).
  | PSRLQ = 554
  /// Shift Packed Data Right Logical (word).
  | PSRLW = 555
  /// Subtract Packed Integers (byte).
  | PSUBB = 556
  /// Subtract Packed Integers (doubleword).
  | PSUBD = 557
  /// Subtract Packed Integers (quadword).
  | PSUBQ = 558
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | PSUBSB = 559
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | PSUBSW = 560
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | PSUBUSB = 561
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | PSUBUSW = 562
  /// Subtract Packed Integers (word).
  | PSUBW = 563
  /// Logical Compare.
  | PTEST = 564
  /// Unpack High Data.
  | PUNPCKHBW = 565
  /// Unpack High Data.
  | PUNPCKHDQ = 566
  /// Unpack High Data.
  | PUNPCKHQDQ = 567
  /// Unpack High Data.
  | PUNPCKHWD = 568
  /// Unpack Low Data.
  | PUNPCKLBW = 569
  /// Unpack Low Data.
  | PUNPCKLDQ = 570
  /// Unpack Low Data.
  | PUNPCKLQDQ = 571
  /// Unpack Low Data.
  | PUNPCKLWD = 572
  /// Push Word, Doubleword or Quadword Onto the Stack.
  | PUSH = 573
  /// Push All General-Purpose Registers (word).
  | PUSHA = 574
  /// Push All General-Purpose Registers (doubleword).
  | PUSHAD = 575
  /// Push EFLAGS Register onto the Stack (16bits of EFLAGS).
  | PUSHF = 576
  /// Push EFLAGS Register onto the Stack (EFLAGS).
  | PUSHFD = 577
  /// Push EFLAGS Register onto the Stack (RFLAGS).
  | PUSHFQ = 578
  /// Logical Exclusive OR.
  | PXOR = 579
  /// Rotate x bits (CF, r/m(x)) left once.
  | RCL = 580
  /// Compute reciprocals of packed single-precision floating-point values.
  | RCPPS = 581
  /// Compute reciprocal of scalar single-precision floating-point values.
  | RCPSS = 582
  /// Rotate x bits (CF, r/m(x)) right once.
  | RCR = 583
  /// Read FS Segment Base.
  | RDFSBASE = 584
  /// Read GS Segment Base.
  | RDGSBASE = 585
  /// Read from Model Specific Register.
  | RDMSR = 586
  /// Read Protection Key Rights for User Pages.
  | RDPKRU = 587
  /// Read Performance-Monitoring Counters.
  | RDPMC = 588
  /// Read Random Number.
  | RDRAND = 589
  /// Read Random SEED.
  | RDSEED = 590
  /// Read shadow stack point (SSP).
  | RDSSPD = 591
  /// Read shadow stack point (SSP).
  | RDSSPQ = 592
  /// Read Time-Stamp Counter.
  | RDTSC = 593
  /// Read Time-Stamp Counter and Processor ID.
  | RDTSCP = 594
  /// Repeat while ECX not zero.
  | REP = 595
  /// Repeat while equal/Repeat while zero.
  | REPE = 596
  /// Repeat while not equal/Repeat while not zero.
  | REPNE = 597
  /// Repeat while not equal/Repeat while not zero.
  | REPNZ = 598
  /// Repeat while equal/Repeat while zero.
  | REPZ = 599
  /// Far return.
  | RETFar = 600
  /// Far return w/ immediate.
  | RETFarImm = 601
  /// Near return.
  | RETNear = 602
  /// Near return w/ immediate .
  | RETNearImm = 603
  /// Rotate x bits r/m(x) left once.
  | ROL = 604
  /// Rotate x bits r/m(x) right once.
  | ROR = 605
  /// Rotate right without affecting arithmetic flags.
  | RORX = 606
  /// Round Packed Double Precision Floating-Point Values.
  | ROUNDPD = 607
  /// Round Packed Single Precision Floating-Point Values.
  | ROUNDPS = 608
  /// Round Scalar Double Precision Floating-Point Values.
  | ROUNDSD = 609
  /// Round Scalar Single Precision Floating-Point Values.
  | ROUNDSS = 610
  /// Resume from System Management Mode.
  | RSM = 611
  /// Compute reciprocals of square roots of packed single-precision FP values.
  | RSQRTPS = 612
  /// Compute reciprocal of square root of scalar single-precision FP values.
  | RSQRTSS = 613
  /// Restore a shadow stack pointer (SSP).
  | RSTORSSP = 614
  /// Store AH into Flags.
  | SAHF = 615
  /// Shift.
  | SAR = 616
  /// Shift arithmetic right.
  | SARX = 617
  /// Save previous shadow stack pointer (SSP).
  | SAVEPREVSSP = 618
  /// Integer Subtraction with Borrow.
  | SBB = 619
  /// Scan String (byte).
  | SCASB = 620
  /// Scan String (doubleword).
  | SCASD = 621
  /// Scan String (quadword).
  | SCASQ = 622
  /// Scan String (word).
  | SCASW = 623
  /// Set byte if above (CF = 0 and ZF = 0).
  | SETA = 624
  /// Set byte if below (CF = 1).
  | SETB = 625
  /// Set byte if below or equal (CF = 1 or ZF = 1).
  | SETBE = 626
  /// Set byte if greater (ZF = 0 and SF = OF).
  | SETG = 627
  /// Set byte if less (SF <> OF).
  | SETL = 628
  /// Set byte if less or equal (ZF = 1 or SF <> OF).
  | SETLE = 629
  /// Set byte if not below (CF = 0).
  | SETNB = 630
  /// Set byte if not less (SF = OF).
  | SETNL = 631
  /// Set byte if not overflow (OF = 0).
  | SETNO = 632
  /// Set byte if not parity (PF = 0).
  | SETNP = 633
  /// Set byte if not sign (SF = 0).
  | SETNS = 634
  /// Set byte if not zero (ZF = 0).
  | SETNZ = 635
  /// Set byte if overflow (OF = 1).
  | SETO = 636
  /// Set byte if parity (PF = 1).
  | SETP = 637
  /// Set byte if sign (SF = 1).
  | SETS = 638
  /// Set busy bit in a supervisor shadow stack token.
  | SETSSBSY = 639
  /// Set byte if sign (ZF = 1).
  | SETZ = 640
  /// Store Fence.
  | SFENCE = 641
  /// Store Global Descriptor Table Register.
  | SGDT = 642
  /// Perform an Intermediate Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG1 = 643
  /// Perform a Final Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG2 = 644
  /// Calculate SHA1 state E after four rounds.
  | SHA1NEXTE = 645
  /// Perform four rounds of SHA1 operations.
  | SHA1RNDS4 = 646
  /// Perform an intermediate calculation for the next 4 SHA256 message dwords.
  | SHA256MSG1 = 647
  /// Perform the final calculation for the next four SHA256 message dwords.
  | SHA256MSG2 = 648
  /// Perform two rounds of SHA256 operations.
  | SHA256RNDS2 = 649
  /// Shift.
  | SHL = 650
  /// Double Precision Shift Left.
  | SHLD = 651
  /// Shift logic left.
  | SHLX = 652
  /// Shift.
  | SHR = 653
  /// Double Precision Shift Right.
  | SHRD = 654
  /// Shift logic right.
  | SHRX = 655
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | SHUFPD = 656
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | SHUFPS = 657
  /// Store Interrupt Descriptor Table Register.
  | SIDT = 658
  /// Store Local Descriptor Table Register.
  | SLDT = 659
  /// Store Machine Status Word.
  | SMSW = 660
  /// Compute packed square roots of packed double-precision FP values.
  | SQRTPD = 661
  /// Compute square roots of packed single-precision floating-point values.
  | SQRTPS = 662
  /// Compute scalar square root of scalar double-precision FP values.
  | SQRTSD = 663
  /// Compute square root of scalar single-precision floating-point values.
  | SQRTSS = 664
  /// Set AC Flag in EFLAGS Register.
  | STAC = 665
  /// Set Carry Flag.
  | STC = 666
  /// Set Direction Flag.
  | STD = 667
  /// Set Interrupt Flag.
  | STI = 668
  /// Store MXCSR Register State.
  | STMXCSR = 669
  /// Store String (store AL).
  | STOSB = 670
  /// Store String (store EAX).
  | STOSD = 671
  /// Store String (store RAX).
  | STOSQ = 672
  /// Store String (store AX).
  | STOSW = 673
  /// Store Task Register.
  | STR = 674
  /// Subtract.
  | SUB = 675
  /// Subtract Packed Double-Precision Floating-Point Values.
  | SUBPD = 676
  /// Subtract Packed Single-Precision Floating-Point Values.
  | SUBPS = 677
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | SUBSD = 678
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | SUBSS = 679
  /// Swap GS Base Register.
  | SWAPGS = 680
  /// Fast System Call.
  | SYSCALL = 681
  /// Fast System Call.
  | SYSENTER = 682
  /// Fast Return from Fast System Call.
  | SYSEXIT = 683
  /// Return From Fast System Call.
  | SYSRET = 684
  /// Logical Compare.
  | TEST = 685
  /// Count the Number of Trailing Zero Bits.
  | TZCNT = 686
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | UCOMISD = 687
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | UCOMISS = 688
  /// Undefined instruction.
  | UD = 689
  /// Undefined Instruction (Raise invalid opcode exception).
  | UD2 = 690
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | UNPCKHPD = 691
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | UNPCKHPS = 692
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | UNPCKLPD = 693
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | UNPCKLPS = 694
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPD = 695
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPS = 696
  /// Add Scalar Double-Precision Floating-Point Values.
  | VADDSD = 697
  /// Add Scalar Single-Precision Floating-Point Values.
  | VADDSS = 698
  /// Perform dword alignment of two concatenated source vectors.
  | VALIGND = 699
  /// Perform qword alignment of two concatenated source vectors.
  | VALIGNQ = 700
  /// Bitwise Logical AND of Packed Double-Precision Floating-Point Values.
  | VANDNPD = 701
  /// Bitwise Logical AND of Packed Single-Precision Floating-Point Values.
  | VANDNPS = 702
  /// Bitwise Logical AND NOT of Packed Double-Precision Floating-Point Values.
  | VANDPD = 703
  /// Bitwise Logical AND NOT of Packed Single-Precision Floating-Point Values.
  | VANDPS = 704
  /// Replace the VBLENDVPD instructions (using opmask as select control).
  | VBLENDMPD = 705
  /// Replace the VBLENDVPS instructions (using opmask as select control).
  | VBLENDMPS = 706
  /// Broadcast 128 bits of int data in mem to low and high 128-bits in ymm1.
  | VBROADCASTI128 = 707
  /// Broadcast Floating-Point Data.
  | VBROADCASTSS = 708
  /// Compare Scalar Ordered Double-Precision FP Values and Set EFLAGS.
  | VCOMISD = 709
  /// Compare Scalar Ordered Single-Precision FP Values and Set EFLAGS.
  | VCOMISS = 710
  /// Compress packed DP elements of a vector.
  | VCOMPRESSPD = 711
  /// Compress packed SP elements of a vector.
  | VCOMPRESSPS = 712
  /// Convert Packed Double-Precision FP Values to Packed Quadword Integers.
  | VCVTPD2QQ = 713
  /// Convert Packed DP FP Values to Packed Unsigned DWord Integers.
  | VCVTPD2UDQ = 714
  /// Convert Packed DP FP Values to Packed Unsigned QWord Integers.
  | VCVTPD2UQQ = 715
  /// Convert 16-bit FP values to Single-Precision FP values.
  | VCVTPH2PS = 716
  /// Convert Single-Precision FP value to 16-bit FP value.
  | VCVTPS2PH = 717
  /// Convert Packed SP FP Values to Packed Signed QWord Int Values.
  | VCVTPS2QQ = 718
  /// Convert Packed SP FP Values to Packed Unsigned DWord Int Values.
  | VCVTPS2UDQ = 719
  /// Convert Packed SP FP Values to Packed Unsigned QWord Int Values.
  | VCVTPS2UQQ = 720
  /// Convert Packed Quadword Integers to Packed Double-Precision FP Values.
  | VCVTQQ2PD = 721
  /// Convert Packed Quadword Integers to Packed Single-Precision FP Values.
  | VCVTQQ2PS = 722
  /// Convert Scalar Double-Precision FP Value to Integer.
  | VCVTSD2SI = 723
  /// Convert Scalar Double-Precision FP Val to Scalar Single-Precision FP Val.
  | VCVTSD2SS = 724
  /// Convert Scalar Double-Precision FP Value to Unsigned Doubleword Integer.
  | VCVTSD2USI = 725
  /// Convert Dword Integer to Scalar Double-Precision FP Value.
  | VCVTSI2SD = 726
  /// Convert Dword Integer to Scalar Single-Precision FP Value.
  | VCVTSI2SS = 727
  /// Convert Scalar Single-Precision FP Val to Scalar Double-Precision FP Val.
  | VCVTSS2SD = 728
  /// Convert Scalar Single-Precision FP Value to Dword Integer.
  | VCVTSS2SI = 729
  /// Convert Scalar Single-Precision FP Value to Unsigned Doubleword Integer.
  | VCVTSS2USI = 730
  /// Convert with Truncation Packed DP FP Values to Packed QWord Integers.
  | VCVTTPD2QQ = 731
  /// Convert with Truncation Packed DP FP Values to Packed Unsigned DWord Int.
  | VCVTTPD2UDQ = 732
  /// Convert with Truncation Packed DP FP Values to Packed Unsigned QWord Int.
  | VCVTTPD2UQQ = 733
  /// Convert with Truncation Packed SP FP Values to Packed Signed QWord Int.
  | VCVTTPS2QQ = 734
  /// Convert with Truncation Packed SP FP Values to Packed Unsigned DWord Int.
  | VCVTTPS2UDQ = 735
  /// Convert with Truncation Packed SP FP Values to Packed Unsigned QWord Int.
  | VCVTTPS2UQQ = 736
  /// Convert with Truncation Scalar Double-Precision FP Value to Signed.
  | VCVTTSD2SI = 737
  /// Convert with Truncation Scalar DP FP Value to Unsigned Integer.
  | VCVTTSD2USI = 738
  /// Convert with Truncation Scalar Single-Precision FP Value to Dword Integer.
  | VCVTTSS2SI = 739
  /// Convert with Truncation Scalar Single-Precision FP Value to Unsigned Int.
  | VCVTTSS2USI = 740
  /// Convert Packed Unsigned DWord Integers to Packed DP FP Values.
  | VCVTUDQ2PD = 741
  /// Convert Packed Unsigned DWord Integers to Packed SP FP Values.
  | VCVTUDQ2PS = 742
  /// Convert Packed Unsigned QWord Integers to Packed DP FP Values.
  | VCVTUQQ2PD = 743
  /// Convert Packed Unsigned QWord Integers to Packed SP FP Values.
  | VCVTUQQ2PS = 744
  /// Convert an unsigned integer to the low DP FP elem and merge to a vector.
  | VCVTUSI2USD = 745
  /// Convert an unsigned integer to the low SP FP elem and merge to a vector.
  | VCVTUSI2USS = 746
  /// Double Block Packed Sum-Absolute-Differences (SAD) on Unsigned Bytes.
  | VDBPSADBW = 747
  /// Divide Packed Double-Precision Floating-Point Values.
  | VDIVPD = 748
  /// Divide Packed Single-Precision Floating-Point Values.
  | VDIVPS = 749
  /// Divide Scalar Double-Precision Floating-Point Values.
  | VDIVSD = 750
  /// Divide Scalar Single-Precision Floating-Point Values.
  | VDIVSS = 751
  /// Verify a Segment for Reading.
  | VERR = 752
  /// Verify a Segment for Writing.
  | VERW = 753
  /// Compute approximate base-2 exponential of packed DP FP elems of a vector.
  | VEXP2PD = 754
  /// Compute approximate base-2 exponential of packed SP FP elems of a vector.
  | VEXP2PS = 755
  /// Compute approximate base-2 exponential of the low DP FP elem of a vector.
  | VEXP2SD = 756
  /// Compute approximate base-2 exponential of the low SP FP elem of a vector.
  | VEXP2SS = 757
  /// Load Sparse Packed Double-Precision FP Values from Dense Memory.
  | VEXPANDPD = 758
  /// Load Sparse Packed Single-Precision FP Values from Dense Memory.
  | VEXPANDPS = 759
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTF32X4 = 760
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTF64X2 = 761
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTF64X4 = 762
  /// Extract a vector from a full-length vector with 32-bit granular update.
  | VEXTRACTI32X4 = 763
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTI64X2 = 764
  /// Extract a vector from a full-length vector with 64-bit granular update.
  | VEXTRACTI64X4 = 765
  /// Fix Up Special Packed Float64 Values.
  | VFIXUPIMMPD = 766
  /// Fix Up Special Packed Float32 Values.
  | VFIXUPIMMPS = 767
  /// Fix Up Special Scalar Float64 Value.
  | VFIXUPIMMSD = 768
  /// Fix Up Special Scalar Float32 Value.
  | VFIXUPIMMSS = 769
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD132SD = 770
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD132SS = 771
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD213SD = 772
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD213SS = 773
  /// Fused Multiply-Add of Scalar Double-Precision Floating-Point Values.
  | VFMADD231SD = 774
  /// Fused Multiply-Add of Scalar Single-Precision Floating-Point Values.
  | VFMADD231SS = 775
  /// Tests Types Of a Packed Float64 Values.
  | VFPCLASSPD = 776
  /// Tests Types Of a Packed Float32 Values.
  | VFPCLASSPS = 777
  /// Tests Types Of a Scalar Float64 Values.
  | VFPCLASSSD = 778
  /// Tests Types Of a Scalar Float32 Values.
  | VFPCLASSSS = 779
  /// Convert Exponents of Packed DP FP Values to DP FP Values.
  | VGETEXPPD = 780
  /// Convert Exponents of Packed SP FP Values to SP FP Values.
  | VGETEXPPS = 781
  /// Convert Exponents of Scalar DP FP Values to DP FP Value.
  | VGETEXPSD = 782
  /// Convert Exponents of Scalar SP FP Values to SP FP Value.
  | VGETEXPSS = 783
  /// Extract Float64 Vector of Normalized Mantissas from Float64 Vector.
  | VGETMANTPD = 784
  /// Extract Float32 Vector of Normalized Mantissas from Float32 Vector.
  | VGETMANTPS = 785
  /// Extract Float64 of Normalized Mantissas from Float64 Scalar.
  | VGETMANTSD = 786
  /// Extract Float32 Vector of Normalized Mantissa from Float32 Vector.
  | VGETMANTSS = 787
  /// Insert Packed Floating-Point Values.
  | VINSERTF32X4 = 788
  /// Insert Packed Floating-Point Values.
  | VINSERTF64X2 = 789
  /// Insert Packed Floating-Point Values.
  | VINSERTF64X4 = 790
  /// Insert Packed Integer Values.
  | VINSERTI128 = 791
  /// Insert Packed Floating-Point Values.
  | VINSERTI64X2 = 792
  /// Load Unaligned Integer 128 Bits.
  | VLDDQU = 793
  /// Call to VM Monitor.
  | VMCALL = 794
  /// Clear Virtual-Machine Control Structure.
  | VMCLEAR = 795
  /// Invoke VM function.
  | VMFUNC = 796
  /// Launch Virtual Machine.
  | VMLAUNCH = 797
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | VMOVAPD = 798
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | VMOVAPS = 799
  /// Move Doubleword.
  | VMOVD = 800
  /// Move One Double-FP and Duplicate.
  | VMOVDDUP = 801
  /// Move Aligned Double Quadword.
  | VMOVDQA = 802
  /// Move Aligned Double Quadword.
  | VMOVDQA32 = 803
  /// Move Aligned Double Quadword.
  | VMOVDQA64 = 804
  /// Move Unaligned Double Quadword.
  | VMOVDQU = 805
  /// VMOVDQU with 16-bit granular conditional update.
  | VMOVDQU16 = 806
  /// Move Unaligned Double Quadword.
  | VMOVDQU32 = 807
  /// Move Unaligned Double Quadword.
  | VMOVDQU64 = 808
  /// VMOVDQU with 8-bit granular conditional update.
  | VMOVDQU8 = 809
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | VMOVHLPS = 810
  /// Move High Packed Double-Precision Floating-Point Value.
  | VMOVHPD = 811
  /// Move High Packed Single-Precision Floating-Point Values.
  | VMOVHPS = 812
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | VMOVLHPS = 813
  /// Move Low Packed Double-Precision Floating-Point Value.
  | VMOVLPD = 814
  /// Move Low Packed Single-Precision Floating-Point Values.
  | VMOVLPS = 815
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | VMOVMSKPD = 816
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | VMOVMSKPS = 817
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | VMOVNTDQ = 818
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPD = 819
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPS = 820
  /// Move Quadword.
  | VMOVQ = 821
  /// Move Data from String to String (doubleword).
  | VMOVSD = 822
  /// Move Packed Single-FP High and Duplicate.
  | VMOVSHDUP = 823
  /// Move Packed Single-FP Low and Duplicate.
  | VMOVSLDUP = 824
  /// Move Scalar Single-Precision Floating-Point Values.
  | VMOVSS = 825
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | VMOVUPD = 826
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | VMOVUPS = 827
  /// Load Pointer to Virtual-Machine Control Structure.
  | VMPTRLD = 828
  /// Store Pointer to Virtual-Machine Control Structure.
  | VMPTRST = 829
  /// Reads a component from the VMCS and stores it into a destination operand.
  | VMREAD = 830
  /// Resume Virtual Machine.
  | VMRESUME = 831
  /// Multiply Packed Double-Precision Floating-Point Values.
  | VMULPD = 832
  /// Multiply Packed Single-Precision Floating-Point Values.
  | VMULPS = 833
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | VMULSD = 834
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | VMULSS = 835
  /// Writes a component to the VMCS from a source operand.
  | VMWRITE = 836
  /// Leave VMX Operation.
  | VMXOFF = 837
  /// Enter VMX Operation.
  | VMXON = 838
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | VORPD = 839
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | VORPS = 840
  /// Packed Absolute Value (byte).
  | VPABSB = 841
  /// Packed Absolute Value (dword).
  | VPABSD = 842
  /// Packed Absolute Value (word).
  | VPABSW = 843
  /// Pack with Signed Saturation.
  | VPACKSSDW = 844
  /// Pack with Signed Saturation.
  | VPACKSSWB = 845
  /// Pack with Unsigned Saturation.
  | VPACKUSDW = 846
  /// Pack with Unsigned Saturation.
  | VPACKUSWB = 847
  /// Add Packed byte Integers.
  | VPADDB = 848
  /// Add Packed Doubleword Integers.
  | VPADDD = 849
  /// Add Packed Quadword Integers.
  | VPADDQ = 850
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | VPADDSB = 851
  /// Add Packed Signed Integers with Signed Saturation (word).
  | VPADDSW = 852
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPADDUSB = 853
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | VPADDUSW = 854
  /// Add Packed word Integers.
  | VPADDW = 855
  /// Packed Align Right.
  | VPALIGNR = 856
  /// Logical AND.
  | VPAND = 857
  /// Logical AND NOT.
  | VPANDN = 858
  /// Average Packed Integers (byte).
  | VPAVGB = 859
  /// Average Packed Integers (word).
  | VPAVGW = 860
  /// Blend Byte/Word Vectors Using an Opmask Control.
  | VPBLENDMB = 861
  /// Blend Int32/Int64 Vectors Using an OpMask Control.
  | VPBLENDMD = 862
  /// Blend qword elements using opmask as select control.
  | VPBLENDMQ = 863
  /// Blend word elements using opmask as select control.
  | VPBLENDMW = 864
  /// Broadcast Integer Data.
  | VPBROADCASTB = 865
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTD = 866
  /// Broadcast Mask to Vector Register.
  | VPBROADCASTM = 867
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTQ = 868
  /// Broadcast from general-purpose register to vector register.
  | VPBROADCASTW = 869
  /// Compare packed signed bytes using specified primitive.
  | VPCMPB = 870
  /// Compare packed signed dwords using specified primitive.
  | VPCMPD = 871
  /// Compare Packed Data for Equal (byte).
  | VPCMPEQB = 872
  /// Compare Packed Data for Equal (doubleword).
  | VPCMPEQD = 873
  /// Compare Packed Data for Equal (quadword).
  | VPCMPEQQ = 874
  /// Compare Packed Data for Equal (word).
  | VPCMPEQW = 875
  /// Packed Compare Explicit Length Strings, Return Index.
  | VPCMPESTRI = 876
  /// Packed Compare Explicit Length Strings, Return Mask.
  | VPCMPESTRM = 877
  /// Compare Packed Signed Integers for Greater Than (byte).
  | VPCMPGTB = 878
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | VPCMPGTD = 879
  /// Compare Packed Data for Greater Than (qword).
  | VPCMPGTQ = 880
  /// Compare Packed Signed Integers for Greater Than (word).
  | VPCMPGTW = 881
  /// Packed Compare Implicit Length Strings, Return Index.
  | VPCMPISTRI = 882
  /// Packed Compare Implicit Length Strings, Return Mask.
  | VPCMPISTRM = 883
  /// Compare packed signed quadwords using specified primitive.
  | VPCMPQ = 884
  /// Compare packed signed words using specified primitive.
  | VPCMPW = 885
  /// Compare packed unsigned bytes using specified primitive.
  | VPCMUB = 886
  /// Compare packed unsigned dwords using specified primitive.
  | VPCMUD = 887
  /// Compare packed unsigned quadwords using specified primitive.
  | VPCMUQ = 888
  /// Compare packed unsigned words using specified primitive.
  | VPCMUW = 889
  /// Store Sparse Packed Doubleword Integer Values into Dense Memory/Register.
  | VPCOMPRESSD = 890
  /// Store Sparse Packed Quadword Integer Values into Dense Memory/Register.
  | VPCOMPRESSQ = 891
  /// Detect conflicts within a vector of packed 32/64-bit integers.
  | VPCONFLICTD = 892
  /// Detect conflicts within a vector of packed 64-bit integers.
  | VPCONFLICTQ = 893
  /// Full Permute of Bytes from Two Tables Overwriting the Index.
  | VPERMI2B = 894
  /// Full permute of two tables of dword elements overwriting the index vector.
  | VPERMI2D = 895
  /// Full permute of two tables of DP elements overwriting the index vector.
  | VPERMI2PD = 896
  /// Full permute of two tables of SP elements overwriting the index vector.
  | VPERMI2PS = 897
  /// Full permute of two tables of qword elements overwriting the index vector.
  | VPERMI2Q = 898
  /// Full Permute From Two Tables Overwriting the Index.
  | VPERMI2W = 899
  /// Full permute of two tables of dword elements overwriting one source table.
  | VPERMT2D = 900
  /// Full permute of two tables of DP elements overwriting one source table.
  | VPERMT2PD = 901
  /// Full permute of two tables of SP elements overwriting one source table.
  | VPERMT2PS = 902
  /// Full permute of two tables of qword elements overwriting one source table.
  | VPERMT2Q = 903
  /// Permute packed word elements.
  | VPERMW = 904
  /// Load Sparse Packed Doubleword Integer Values from Dense Memory / Register.
  | VPEXPANDD = 905
  /// Load Sparse Packed Quadword Integer Values from Dense Memory / Register.
  | VPEXPANDQ = 906
  /// Extract Word.
  | VPEXTRW = 907
  /// Packed Horizontal Add (32-bit).
  | VPHADDD = 908
  /// Packed Horizontal Add and Saturate (16-bit).
  | VPHADDSW = 909
  /// Packed Horizontal Add (16-bit).
  | VPHADDW = 910
  /// Packed Horizontal Word Minimum.
  | VPHMINPOSUW = 911
  /// Packed Horizontal Subtract (32-bit).
  | VPHSUBD = 912
  /// Packed Horizontal Subtract and Saturate (16-bit)
  | VPHSUBSW = 913
  /// Packed Horizontal Subtract (16-bit).
  | VPHSUBW = 914
  /// Insert Byte.
  | VPINSRB = 915
  /// Insert Word.
  | VPINSRW = 916
  /// Count the number of leading zero bits of packed dword elements.
  | VPLZCNTD = 917
  /// Count the number of leading zero bits of packed qword elements.
  | VPLZCNTQ = 918
  /// Multiply and Add Packed Integers.
  | VPMADDWD = 919
  /// Maximum of Packed Signed Integers (byte).
  | VPMAXSB = 920
  /// Maximum of Packed Signed Integers (dword).
  | VPMAXSD = 921
  /// Compute maximum of packed signed 64-bit integer elements.
  | VPMAXSQ = 922
  /// Maximum of Packed Signed Word Integers.
  | VPMAXSW = 923
  /// Maximum of Packed Unsigned Byte Integers.
  | VPMAXUB = 924
  /// Maximum of Packed Unsigned Integers (dword).
  | VPMAXUD = 925
  /// Compute maximum of packed unsigned 64-bit integer elements.
  | VPMAXUQ = 926
  /// Maximum of Packed Unsigned Integers (word).
  | VPMAXUW = 927
  /// Minimum of Packed Signed Integers (byte).
  | VPMINSB = 928
  /// Minimum of Packed Signed Integers (dword).
  | VPMINSD = 929
  /// Compute minimum of packed signed 64-bit integer elements.
  | VPMINSQ = 930
  /// Minimum of Packed Signed Word Integers.
  | VPMINSW = 931
  /// Minimum of Packed Unsigned Byte Integers.
  | VPMINUB = 932
  /// Minimum of Packed Dword Integers.
  | VPMINUD = 933
  /// Compute minimum of packed unsigned 64-bit integer elements.
  | VPMINUQ = 934
  /// Minimum of Packed Unsigned Integers (word).
  | VPMINUW = 935
  /// Convert a vector register in 32/64-bit granularity to an opmask register.
  | VPMOVB2D = 936
  /// Convert a Vector Register to a Mask.
  | VPMOVB2M = 937
  /// Down Convert DWord to Byte.
  | VPMOVDB = 938
  /// Down Convert DWord to Word.
  | VPMOVDW = 939
  /// Convert opmask register to vector register in 8-bit granularity.
  | VPMOVM2B = 940
  /// Convert opmask register to vector register in 32-bit granularity.
  | VPMOVM2D = 941
  /// Convert opmask register to vector register in 64-bit granularity.
  | VPMOVM2Q = 942
  /// Convert opmask register to vector register in 16-bit granularity.
  | VPMOVM2W = 943
  /// Move Byte Mask.
  | VPMOVMSKB = 944
  /// Convert a Vector Register to a Mask.
  | VPMOVQ2M = 945
  /// Down Convert QWord to Byte.
  | VPMOVQB = 946
  /// Down Convert QWord to DWord.
  | VPMOVQD = 947
  /// Down Convert QWord to Word.
  | VPMOVQW = 948
  /// Down Convert DWord to Byte.
  | VPMOVSDB = 949
  /// Down Convert DWord to Word.
  | VPMOVSDW = 950
  /// Down Convert QWord to Byte.
  | VPMOVSQB = 951
  /// Down Convert QWord to Dword.
  | VPMOVSQD = 952
  /// Down Convert QWord to Word.
  | VPMOVSQW = 953
  /// Down Convert Word to Byte.
  | VPMOVSWB = 954
  /// Packed Move with Sign Extend (8-bit to 32-bit).
  | VPMOVSXBD = 955
  /// Packed Move with Sign Extend (8-bit to 64-bit).
  | VPMOVSXBQ = 956
  /// Packed Move with Sign Extend (8-bit to 16-bit).
  | VPMOVSXBW = 957
  /// Packed Move with Sign Extend (32-bit to 64-bit).
  | VPMOVSXDQ = 958
  /// Packed Move with Sign Extend (16-bit to 32-bit).
  | VPMOVSXWD = 959
  /// Packed Move with Sign Extend (16-bit to 64-bit).
  | VPMOVSXWQ = 960
  /// Down Convert DWord to Byte.
  | VPMOVUSDB = 961
  /// Down Convert DWord to Word.
  | VPMOVUSDW = 962
  /// Down Convert QWord to Byte.
  | VPMOVUSQB = 963
  /// Down Convert QWord to DWord
  | VPMOVUSQD = 964
  /// Down Convert QWord to Dword.
  | VPMOVUSQW = 965
  /// Down Convert Word to Byte.
  | VPMOVUSWB = 966
  /// Convert a vector register in 16-bit granularity to an opmask register.
  | VPMOVW2M = 967
  /// Down convert word elements in a vector to byte elements using truncation.
  | VPMOVWB = 968
  /// Packed Move with Zero Extend (8-bit to 32-bit).
  | VPMOVZXBD = 969
  /// Packed Move with Zero Extend (8-bit to 64-bit).
  | VPMOVZXBQ = 970
  /// Packed Move with Zero Extend (8-bit to 16-bit).
  | VPMOVZXBW = 971
  /// Packed Move with Zero Extend (32-bit to 64-bit).
  | VPMOVZXDQ = 972
  /// Packed Move with Zero Extend (16-bit to 32-bit).
  | VPMOVZXWD = 973
  /// Packed Move with Zero Extend (16-bit to 64-bit).
  | VPMOVZXWQ = 974
  /// Multiply Packed Doubleword Integers.
  | VPMULDQ = 975
  /// Packed Multiply High with Round and Scale.
  | VPMULHRSW = 976
  /// Multiply Packed Unsigned Integers and Store High Result.
  | VPMULHUW = 977
  /// Multiply Packed Signed Integers and Store High Result.
  | VPMULHW = 978
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLD = 979
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLQ = 980
  /// Multiply Packed Signed Integers and Store Low Result.
  | VPMULLW = 981
  /// Multiply Packed Unsigned Doubleword Integers.
  | VPMULUDQ = 982
  /// Bitwise Logical OR.
  | VPOR = 983
  /// Rotate dword elem left by a constant shift count with conditional update.
  | VPROLD = 984
  /// Rotate qword elem left by a constant shift count with conditional update.
  | VPROLQ = 985
  /// Rotate dword element left by shift counts specified.
  | VPROLVD = 986
  /// Rotate qword element left by shift counts specified.
  | VPROLVQ = 987
  /// Rotate dword element right by a constant shift count.
  | VPRORD = 988
  /// Rotate qword element right by a constant shift count.
  | VPRORQ = 989
  /// Rotate dword element right by shift counts specified.
  | VPRORRD = 990
  /// Rotate qword element right by shift counts specified.
  | VPRORRQ = 991
  /// Compute Sum of Absolute Differences.
  | VPSADBW = 992
  /// Scatter dword elements in a vector to memory using dword indices.
  | VPSCATTERDD = 993
  /// Scatter qword elements in a vector to memory using dword indices.
  | VPSCATTERDQ = 994
  /// Scatter dword elements in a vector to memory using qword indices.
  | VPSCATTERQD = 995
  /// Scatter qword elements in a vector to memory using qword indices.
  | VPSCATTERQQ = 996
  /// Packed Shuffle Bytes.
  | VPSHUFB = 997
  /// Shuffle Packed Doublewords.
  | VPSHUFD = 998
  /// Shuffle Packed High Words.
  | VPSHUFHW = 999
  /// Shuffle Packed Low Words.
  | VPSHUFLW = 1000
  /// Packed SIGN (byte).
  | VPSIGNB = 1001
  /// Packed SIGN (doubleword).
  | VPSIGND = 1002
  /// Packed SIGN (word).
  | VPSIGNW = 1003
  /// Shift Packed Data Left Logical (doubleword).
  | VPSLLD = 1004
  /// Shift Double Quadword Left Logical.
  | VPSLLDQ = 1005
  /// Shift Packed Data Left Logical (quadword).
  | VPSLLQ = 1006
  /// Variable Bit Shift Left Logical.
  | VPSLLVW = 1007
  /// Shift Packed Data Left Logical (word).
  | VPSLLW = 1008
  /// Shift Packed Data Right Arithmetic (doubleword).
  | VPSRAD = 1009
  /// Shift qwords right by a constant shift count and shifting in sign bits.
  | VPSRAQ = 1010
  /// Shift qwords right by shift counts in a vector and shifting in sign bits.
  | VPSRAVQ = 1011
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVW = 1012
  /// Shift Packed Data Right Arithmetic (word).
  | VPSRAW = 1013
  /// Shift Packed Data Right Logical (doubleword).
  | VPSRLD = 1014
  /// Shift Double Quadword Right Logical.
  | VPSRLDQ = 1015
  /// Shift Packed Data Right Logical (quadword).
  | VPSRLQ = 1016
  /// Variable Bit Shift Right Logical.
  | VPSRLVW = 1017
  /// Shift Packed Data Right Logical (word).
  | VPSRLW = 1018
  /// Subtract Packed Integers (byte).
  | VPSUBB = 1019
  /// Subtract Packed Integers (doubleword).
  | VPSUBD = 1020
  /// Subtract Packed Integers (quadword).
  | VPSUBQ = 1021
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | VPSUBSB = 1022
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | VPSUBSW = 1023
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPSUBUSB = 1024
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | VPSUBUSW = 1025
  /// Subtract Packed Integers (word).
  | VPSUBW = 1026
  /// Perform bitwise ternary logic operation of three vectors.
  | VPTERLOGD = 1027
  /// Perform bitwise ternary logic operation of three vectors.
  | VPTERLOGQ = 1028
  /// Logical Compare.
  | VPTEST = 1029
  /// Perform bitwise AND of byte elems of two vecs and write results to opmask.
  | VPTESTMB = 1030
  /// Perform bitwise AND of dword elems of 2-vecs and write results to opmask.
  | VPTESTMD = 1031
  /// Perform bitwise AND of qword elems of 2-vecs and write results to opmask.
  | VPTESTMQ = 1032
  /// Perform bitwise AND of word elems of two vecs and write results to opmask.
  | VPTESTMW = 1033
  /// Perform bitwise NAND of byte elems of 2-vecs and write results to opmask.
  | VPTESTNMB = 1034
  /// Perform bitwise NAND of dword elems of 2-vecs and write results to opmask.
  | VPTESTNMD = 1035
  /// Perform bitwise NAND of qword elems of 2-vecs and write results to opmask.
  | VPTESTNMQ = 1036
  /// Perform bitwise NAND of word elems of 2-vecs and write results to opmask.
  | VPTESTNMW = 1037
  /// Unpack High Data.
  | VPUNPCKHBW = 1038
  /// Unpack High Data.
  | VPUNPCKHDQ = 1039
  /// Unpack High Data.
  | VPUNPCKHQDQ = 1040
  /// Unpack High Data.
  | VPUNPCKHWD = 1041
  /// Unpack Low Data.
  | VPUNPCKLBW = 1042
  /// Unpack Low Data.
  | VPUNPCKLDQ = 1043
  /// Unpack Low Data.
  | VPUNPCKLQDQ = 1044
  /// Unpack Low Data.
  | VPUNPCKLWD = 1045
  /// Logical Exclusive OR.
  | VPXOR = 1046
  /// Range Restriction Calculation For Packed Pairs of Float64 Values.
  | VRANGEPD = 1047
  /// Range Restriction Calculation For Packed Pairs of Float32 Values.
  | VRANGEPS = 1048
  /// Range Restriction Calculation From a pair of Scalar Float64 Values.
  | VRANGESD = 1049
  /// Range Restriction Calculation From a Pair of Scalar Float32 Values.
  | VRANGESS = 1050
  /// Compute Approximate Reciprocals of Packed Float64 Values.
  | VRCP14PD = 1051
  /// Compute Approximate Reciprocals of Packed Float32 Values.
  | VRCP14PS = 1052
  /// Compute Approximate Reciprocal of Scalar Float64 Value.
  | VRCP14SD = 1053
  /// Compute Approximate Reciprocal of Scalar Float32 Value.
  | VRCP14SS = 1054
  /// Computes the reciprocal approximation of the float64 values.
  | VRCP28PD = 1055
  /// Computes the reciprocal approximation of the float32 values.
  | VRCP28PS = 1056
  /// Computes the reciprocal approximation of the low float64 value.
  | VRCP28SD = 1057
  /// Computes the reciprocal approximation of the low float32 value.
  | VRCP28SS = 1058
  /// Perform Reduction Transformation on Packed Float64 Values.
  | VREDUCEPD = 1059
  /// Perform Reduction Transformation on Packed Float32 Values.
  | VREDUCEPS = 1060
  /// Perform a Reduction Transformation on a Scalar Float64 Value.
  | VREDUCESD = 1061
  /// Perform a Reduction Transformation on a Scalar Float32 Value.
  | VREDUCESS = 1062
  /// Round Packed Float64 Values To Include A Given Number Of Fraction Bits.
  | VRNDSCALEPD = 1063
  /// Round Packed Float32 Values To Include A Given Number Of Fraction Bits.
  | VRNDSCALEPS = 1064
  /// Round Scalar Float64 Value To Include A Given Number Of Fraction Bits.
  | VRNDSCALESD = 1065
  /// Round Scalar Float32 Value To Include A Given Number Of Fraction Bits.
  | VRNDSCALESS = 1066
  /// Compute Approximate Reciprocals of Square Roots of Packed Float64 Values.
  | VRSQRT14PD = 1067
  /// Compute Approximate Reciprocals of Square Roots of Packed Float32 Values.
  | VRSQRT14PS = 1068
  /// Compute Approximate Reciprocal of Square Root of Scalar Float64 Value.
  | VRSQRT14SD = 1069
  /// Compute Approximate Reciprocal of Square Root of Scalar Float32 Value.
  | VRSQRT14SS = 1070
  /// Computes the reciprocal square root of the float64 values.
  | VRSQRT28PD = 1071
  /// Computes the reciprocal square root of the float32 values.
  | VRSQRT28PS = 1072
  /// Computes the reciprocal square root of the low float64 value.
  | VRSQRT28SD = 1073
  /// Computes the reciprocal square root of the low float32 value.
  | VRSQRT28SS = 1074
  /// Multiply packed DP FP elements of a vector by powers.
  | VSCALEPD = 1075
  /// Multiply packed SP FP elements of a vector by powers.
  | VSCALEPS = 1076
  /// Multiply the low DP FP element of a vector by powers.
  | VSCALESD = 1077
  /// Multiply the low SP FP element of a vector by powers.
  | VSCALESS = 1078
  /// Scatter SP/DP FP elements in a vector to memory using dword indices.
  | VSCATTERDD = 1079
  /// Scatter SP/DP FP elements in a vector to memory using dword indices.
  | VSCATTERDQ = 1080
  /// Scatter SP/DP FP elements in a vector to memory using qword indices.
  | VSCATTERQD = 1081
  /// Scatter SP/DP FP elements in a vector to memory using qword indices.
  | VSCATTERQQ = 1082
  /// Shuffle 128-bit lanes of a vector with 32 bit granular conditional update.
  | VSHUFF32X4 = 1083
  /// Shuffle 128-bit lanes of a vector with 64 bit granular conditional update.
  | VSHUFF64X2 = 1084
  /// Shuffle 128-bit lanes of a vector with 32 bit granular conditional update.
  | VSHUFI32X4 = 1085
  /// Shuffle 128-bit lanes of a vector with 64 bit granular conditional update.
  | VSHUFI64X2 = 1086
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | VSHUFPD = 1087
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | VSHUFPS = 1088
  /// Compute packed square roots of packed double-precision FP values.
  | VSQRTPD = 1089
  /// Compute square roots of packed single-precision floating-point values.
  | VSQRTPS = 1090
  /// Compute scalar square root of scalar double-precision FP values.
  | VSQRTSD = 1091
  /// Compute square root of scalar single-precision floating-point values.
  | VSQRTSS = 1092
  /// Subtract Packed Double-Precision Floating-Point Values.
  | VSUBPD = 1093
  /// Subtract Packed Single-Precision Floating-Point Values.
  | VSUBPS = 1094
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | VSUBSD = 1095
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | VSUBSS = 1096
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | VUCOMISD = 1097
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | VUCOMISS = 1098
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | VUNPCKHPD = 1099
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | VUNPCKHPS = 1100
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | VUNPCKLPD = 1101
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | VUNPCKLPS = 1102
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | VXORPD = 1103
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | VXORPS = 1104
  /// Zero Upper Bits of YMM Registers.
  | VZEROUPPER = 1105
  /// Wait.
  | WAIT = 1106
  /// Write Back and Invalidate Cache.
  | WBINVD = 1107
  /// Write FS Segment Base.
  | WRFSBASE = 1108
  /// Write GS Segment Base.
  | WRGSBASE = 1109
  /// Write to Model Specific Register.
  | WRMSR = 1110
  /// Write Data to User Page Key Register.
  | WRPKRU = 1111
  /// Write to a shadow stack.
  | WRSSD = 1112
  /// Write to a shadow stack.
  | WRSSQ = 1113
  /// Write to a user mode shadow stack.
  | WRUSSD = 1114
  /// Write to a user mode shadow stack.
  | WRUSSQ = 1115
  /// Transactional Abort.
  | XABORT = 1116
  /// Prefix hint to the beginning of an HLE transaction region.
  | XACQUIRE = 1117
  /// Exchange and Add.
  | XADD = 1118
  /// Transactional Begin.
  | XBEGIN = 1119
  /// Exchange Register/Memory with Register.
  | XCHG = 1120
  /// Transactional End.
  | XEND = 1121
  /// Value of Extended Control Register.
  | XGETBV = 1122
  /// Table lookup translation.
  | XLAT = 1123
  /// Table Look-up Translation.
  | XLATB = 1124
  /// Logical Exclusive OR.
  | XOR = 1125
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | XORPD = 1126
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | XORPS = 1127
  /// Prefix hint to the end of an HLE transaction region.
  | XRELEASE = 1128
  /// Restore Processor Extended States.
  | XRSTOR = 1129
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS = 1130
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS64 = 1131
  /// Save Processor Extended States.
  | XSAVE = 1132
  /// Save processor extended states with compaction to memory.
  | XSAVEC = 1133
  /// Save processor extended states with compaction to memory.
  | XSAVEC64 = 1134
  /// Save Processor Extended States Optimized.
  | XSAVEOPT = 1135
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES = 1136
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES64 = 1137
  /// Set Extended Control Register.
  | XSETBV = 1138
  /// Test If In Transactional Execution.
  | XTEST = 1139
  /// Invalid Opcode.
  | InvalOP = 1140

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
