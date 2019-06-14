(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Seung Il Jung <sijung@kaist.ac.kr>
          DongYeop Oh <oh51dy@kaist.ac.kr>

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

exception internal NotEncodableOn64Exception

/// Instruction prefixes.
type Prefix =
  | PrxNone = 0x0       (* No prefix *)
  | PrxLOCK = 0x1       (* Group 1 *)
  | PrxREPNZ = 0x2
  | PrxREPZ = 0x4
  | PrxCS = 0x8         (* Group 2 *)
  | PrxSS = 0x10
  | PrxDS = 0x20
  | PrxES = 0x40
  | PrxFS = 0x80
  | PrxGS = 0x100
  | PrxOPSIZE = 0x200   (* Group 3 *)
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
  /// Add.
  | ADD = 5
  /// Add Packed Double-Precision Floating-Point Values.
  | ADDPD = 6
  /// Add Packed Single-Precision Floating-Point Values.
  | ADDPS = 7
  /// Add Scalar Double-Precision Floating-Point Values.
  | ADDSD = 8
  /// Add Scalar Single-Precision Floating-Point Values.
  | ADDSS = 9
  /// Logical AND.
  | AND = 10
  /// Bitwise Logical AND of Packed Double-Precision Floating-Point Values.
  | ANDNPD = 11
  /// Bitwise Logical AND of Packed Single-Precision Floating-Point Values.
  | ANDNPS = 12
  /// Bitwise Logical AND NOT of Packed Double-Precision Floating-Point Values.
  | ANDPD = 13
  /// Bitwise Logical AND NOT of Packed Single-Precision Floating-Point Values.
  | ANDPS = 14
  /// Adjust RPL Field of Segment Selector.
  | ARPL = 15
  /// Move Bounds.
  | BNDMOV = 16
  /// Check Array Index Against Bounds.
  | BOUND = 17
  /// Bit Scan Forward.
  | BSF = 18
  /// Bit Scan Reverse.
  | BSR = 19
  /// Byte Swap.
  | BSWAP = 20
  /// Bit Test.
  | BT = 21
  /// Bit Test and Complement.
  | BTC = 22
  /// Bit Test and Reset.
  | BTR = 23
  /// Bit Test and Set.
  | BTS = 24
  /// Far call.
  | CALLFar = 25
  /// Near call.
  | CALLNear = 26
  /// Convert Byte to Word.
  | CBW = 27
  /// Convert Doubleword to Quadword.
  | CDQ = 28
  /// Convert Doubleword to Quadword.
  | CDQE = 29
  /// Clear AC Flag in EFLAGS Register.
  | CLAC = 30
  /// Clear Carry Flag.
  | CLC = 31
  /// Clear Direction Flag.
  | CLD = 32
  /// Flush Cache Line.
  | CLFLUSH = 33
  /// Clear Interrupt Flag.
  | CLI = 34
  /// Clear Task-Switched Flag in CR0.
  | CLTS = 35
  /// Complement Carry Flag.
  | CMC = 36
  /// Conditional Move (Move if above (CF=0 and ZF=0)).
  | CMOVA = 37
  /// Conditional Move (Move if above or equal (CF=0)).
  | CMOVAE = 38
  /// Conditional Move (Move if below (CF=1)).
  | CMOVB = 39
  /// Conditional Move (Move if below or equal (CF=1 or ZF=1)).
  | CMOVBE = 40
  /// Conditional Move (Move if greater (ZF=0 and SF=OF)).
  | CMOVG = 41
  /// Conditional Move (Move if greater or equal (SF=OF)).
  | CMOVGE = 42
  /// Conditional Move (Move if less (SF≠OF)).
  | CMOVL = 43
  /// Conditional Move (Move if less or equal (ZF=1 or SF≠OF)).
  | CMOVLE = 44
  /// Conditional Move (Move if not overflow (OF=0)).
  | CMOVNO = 45
  /// Conditional Move (Move if not parity (PF=0)).
  | CMOVNP = 46
  /// Conditional Move (Move if not sign (SF=0)).
  | CMOVNS = 47
  /// Conditional Move (Move if not zero (ZF=0)).
  | CMOVNZ = 48
  /// Conditional Move (Move if overflow (OF=1)).
  | CMOVO = 49
  /// Conditional Move (Move if parity (PF=1)).
  | CMOVP = 50
  /// Conditional Move (Move if sign (SF=1)).
  | CMOVS = 51
  /// Conditional Move (Move if zero (ZF=1)).
  | CMOVZ = 52
  /// Compare Two Operands.
  | CMP = 53
  /// Compare packed double-precision floating-point values.
  | CMPPD = 54
  /// Compare packed single-precision floating-point values.
  | CMPPS = 55
  /// Compare String Operands (byte).
  | CMPSB = 56
  /// Compare String Operands (dword) or Compare scalar dbl-precision FP values.
  | CMPSD = 57
  /// Compare String Operands (quadword).
  | CMPSQ = 58
  /// Compare scalar single-precision floating-point values.
  | CMPSS = 59
  /// Compare String Operands (word).
  | CMPSW = 60
  /// Compare and Exchange.
  | CMPXCHG = 61
  /// Compare and Exchange Bytes.
  | CMPXCHG16B = 62
  /// Compare and Exchange Bytes.
  | CMPXCHG8B = 63
  /// Compare Scalar Ordered Double-Precision FP Values and Set EFLAGS.
  | COMISD = 64
  /// Compare Scalar Ordered Single-Precision FP Values and Set EFLAGS.
  | COMISS = 65
  /// CPU Identification.
  | CPUID = 66
  /// Convert Quadword to Octaword.
  | CQO = 67
  /// Accumulate CRC32 Value.
  | CRC32 = 68
  /// Convert Packed Dword Integers to Packed Double-Precision FP Values.
  | CVTDQ2PD = 69
  /// Convert Packed Dword Integers to Packed Single-Precision FP Values.
  | CVTDQ2PS = 70
  /// Convert Packed Double-Precision FP Values to Packed Dword Integers.
  | CVTPD2DQ = 71
  /// Convert Packed Double-Precision FP Values to Packed Dword Integers.
  | CVTPD2PI = 72
  /// Convert Packed Double-Precision FP Values to Packed Single-Precision FP.
  | CVTPD2PS = 73
  /// Convert Packed Dword Integers to Packed Double-Precision FP Values.
  | CVTPI2PD = 74
  /// Convert Packed Dword Integers to Packed Single-Precision FP Values.
  | CVTPI2PS = 75
  /// Convert Packed Single-Precision FP Values to Packed Dword Integers.
  | CVTPS2DQ = 76
  /// Convert Packed Single-Precision FP Values to Packed Double-Precision FP.
  | CVTPS2PD = 77
  /// Convert Packed Single-Precision FP Values to Packed Dword Integers.
  | CVTPS2PI = 78
  /// Convert Scalar Double-Precision FP Value to Integer.
  | CVTSD2SI = 79
  /// Convert Scalar Double-Precision FP Value to Scalar Single-Precision FP.
  | CVTSD2SS = 80
  /// Convert Dword Integer to Scalar Double-Precision FP Value.
  | CVTSI2SD = 81
  /// Convert Dword Integer to Scalar Single-Precision FP Value.
  | CVTSI2SS = 82
  /// Convert Scalar Single-Precision FP Value to Scalar Double-Precision FP.
  | CVTSS2SD = 83
  /// Convert Scalar Single-Precision FP Value to Dword Integer.
  | CVTSS2SI = 84
  /// Convert with Truncation Packed Double-Precision FP Values to Packed Dword.
  | CVTTPD2DQ = 85
  /// Convert with Truncation Packed Double-Precision FP Values to Packed Dword.
  | CVTTPD2PI = 86
  /// Convert with Truncation Packed Single-Precision FP Values to Packed Dword.
  | CVTTPS2DQ = 87
  /// Convert with Truncation Packed Single-Precision FP Values to Packed Dword.
  | CVTTPS2PI = 88
  /// Convert with Truncation Scalar Double-Precision FP Value to Signed.
  | CVTTSD2SI = 89
  /// Convert with Truncation Scalar Single-Precision FP Value to Dword Integer.
  | CVTTSS2SI = 90
  /// Convert Word to Doubleword.
  | CWD = 91
  /// Convert Word to Doubleword.
  | CWDE = 92
  /// Decimal Adjust AL after Addition.
  | DAA = 93
  /// Decimal Adjust AL after Subtraction.
  | DAS = 94
  /// Decrement by 1.
  | DEC = 95
  /// Unsigned Divide.
  | DIV = 96
  /// Divide Packed Double-Precision Floating-Point Values.
  | DIVPD = 97
  /// Divide Packed Single-Precision Floating-Point Values.
  | DIVPS = 98
  /// Divide Scalar Double-Precision Floating-Point Values.
  | DIVSD = 99
  /// Divide Scalar Single-Precision Floating-Point Values.
  | DIVSS = 100
  /// Make Stack Frame for Procedure Parameters.
  | ENTER = 101
  /// Compute 2x-1.
  | F2XM1 = 102
  /// Absolute Value.
  | FABS = 103
  /// Add.
  | FADD = 104
  /// Add and pop the register stack.
  | FADDP = 105
  /// Load Binary Coded Decimal.
  | FBLD = 106
  /// Store BCD Integer and Pop.
  | FBSTP = 107
  /// Change Sign.
  | FCHS = 108
  /// Clear Exceptions.
  | FCLEX = 109
  /// Floating-Point Conditional Move (if below (CF=1)).
  | FCMOVB = 110
  /// Floating-Point Conditional Move (if below or equal (CF=1 or ZF=1)).
  | FCMOVBE = 111
  /// Floating-Point Conditional Move (if equal (ZF=1)).
  | FCMOVE = 112
  /// Floating-Point Conditional Move (if not below (CF=0)).
  | FCMOVNB = 113
  /// Floating-Point Conditional Move (if not below or equal (CF=0 and ZF=0)).
  | FCMOVNBE = 114
  /// Floating-Point Conditional Move (if not equal (ZF=0)).
  | FCMOVNE = 115
  /// Floating-Point Conditional Move (if not unordered (PF=0)).
  | FCMOVNU = 116
  /// Floating-Point Conditional Move (if unordered (PF=1)).
  | FCMOVU = 117
  /// Compare Floating Point Values.
  | FCOM = 118
  /// Compare Floating Point Values and Set EFLAGS.
  | FCOMI = 119
  /// Compare Floating Point Values and Set EFLAGS.
  | FCOMIP = 120
  /// Compare Floating Point Values and pop register stack.
  | FCOMP = 121
  /// Compare Floating Point Values and pop register stack twice.
  | FCOMPP = 122
  /// Cosine.
  | FCOS = 123
  /// Decrement Stack-Top Pointer.
  | FDECSTP = 124
  /// Divide.
  | FDIV = 125
  /// Divide and pop the register stack.
  | FDIVP = 126
  /// Reverse Divide.
  | FDIVR = 127
  /// Reverse Divide and pop the register stack.
  | FDIVRP = 128
  /// Free Floating-Point Register.
  | FFREE = 129
  /// Add.
  | FIADD = 130
  /// Compare Integer.
  | FICOM = 131
  /// Compare Integer and pop the register stack.
  | FICOMP = 132
  /// Divide.
  | FIDIV = 133
  /// Reverse Divide.
  | FIDIVR = 134
  /// Load Integer.
  | FILD = 135
  /// Multiply.
  | FIMUL = 136
  /// Increment Stack-Top Pointer.
  | FINCSTP = 137
  /// Initialize Floating-Point Unit.
  | FINIT = 138
  /// Store Integer.
  | FIST = 139
  /// Store Integer and pop the register stack.
  | FISTP = 140
  /// Store Integer with Truncation.
  | FISTTP = 141
  /// Subtract.
  | FISUB = 142
  /// Reverse Subtract.
  | FISUBR = 143
  /// Load Floating Point Value.
  | FLD = 144
  /// Load Constant (Push +1.0 onto the FPU register stack).
  | FLD1 = 145
  /// Load x87 FPU Control Word.
  | FLDCW = 146
  /// Load x87 FPU Environment.
  | FLDENV = 147
  /// Load Constant (Push log2e onto the FPU register stack).
  | FLDL2E = 148
  /// Load Constant (Push log210 onto the FPU register stack).
  | FLDL2T = 149
  /// Load Constant (Push log102 onto the FPU register stack).
  | FLDLG2 = 150
  /// Load Constant (Push loge2 onto the FPU register stack).
  | FLDLN2 = 151
  /// Load Constant (Push Pi onto the FPU register stack).
  | FLDPI = 152
  /// Load Constant (Push +0.0 onto the FPU register stack).
  | FLDZ = 153
  /// Multiply.
  | FMUL = 154
  /// Multiply and pop the register stack.
  | FMULP = 155
  /// No Operation.
  | FNOP = 156
  /// Partial Arctangent.
  | FPATAN = 157
  /// Partial Remainder.
  | FPREM = 158
  /// Partial Remainder.
  | FPREM1 = 159
  /// Partial Tangent.
  | FPTAN = 160
  /// Round to Integer.
  | FRNDINT = 161
  /// Restore x87 FPU State.
  | FRSTOR = 162
  /// Store x87 FPU State.
  | FSAVE = 163
  /// Scale.
  | FSCALE = 164
  /// Sine.
  | FSIN = 165
  /// Sine and Cosine.
  | FSINCOS = 166
  /// Square Root.
  | FSQRT = 167
  /// Store Floating Point Value.
  | FST = 168
  /// Store x87 FPU Control Word.
  | FSTCW = 169
  /// Store x87 FPU Environment.
  | FSTENV = 170
  /// Store Floating Point Value.
  | FSTP = 171
  /// Store x87 FPU Status Word.
  | FSTSW = 172
  /// Subtract.
  | FSUB = 173
  /// Subtract and pop register stack.
  | FSUBP = 174
  /// Reverse Subtract.
  | FSUBR = 175
  /// Reverse Subtract and pop register stack.
  | FSUBRP = 176
  /// TEST.
  | FTST = 177
  /// Unordered Compare Floating Point Values.
  | FUCOM = 178
  /// Compare Floating Point Values and Set EFLAGS.
  | FUCOMI = 179
  /// Compare Floating Point Values and Set EFLAGS and pop register stack.
  | FUCOMIP = 180
  /// Unordered Compare Floating Point Values.
  | FUCOMP = 181
  /// Unordered Compare Floating Point Values.
  | FUCOMPP = 182
  /// Examine ModR/M.
  | FXAM = 183
  /// Exchange Register Contents.
  | FXCH = 184
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR = 185
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR64 = 186
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE = 187
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE64 = 188
  /// Extract Exponent and Significand.
  | FXTRACT = 189
  /// compute y * log2x.
  | FYL2X = 190
  /// compute y * log2(x+1).
  | FYL2XP1 = 191
  /// GETSEC.
  | GETSEC = 192
  /// Halt.
  | HLT = 193
  /// Signed Divide.
  | IDIV = 194
  /// Signed Multiply.
  | IMUL = 195
  /// Input from Port.
  | IN = 196
  /// Increment by 1.
  | INC = 197
  /// Input from Port to String.
  | INS = 198
  /// Input from Port to String (byte).
  | INSB = 199
  /// Input from Port to String (doubleword).
  | INSD = 200
  /// Input from Port to String (word).
  | INSW = 201
  /// Call to Interrupt (Interrupt vector specified by immediate byte).
  | INT = 202
  /// Call to Interrupt (Interrupt 3?trap to debugger).
  | INT3 = 203
  /// Call to Interrupt (InteInterrupt 4?if overflow flag is 1).
  | INTO = 204
  /// Invalidate Internal Caches.
  | INVD = 205
  /// Invalidate TLB Entries.
  | INVLPG = 206
  /// Interrupt return (32-bit operand size).
  | IRETD = 207
  /// Interrupt return (64-bit operand size).
  | IRETQ = 208
  /// Interrupt return (16-bit operand size).
  | IRETW = 209
  /// Jump if Condition Is Met (Jump short if above, CF=0 and ZF=0).
  | JA = 210
  /// Jump if Condition Is Met (Jump short if below, CF=1).
  | JB = 211
  /// Jump if Condition Is Met (Jump short if below or equal, CF=1 or ZF).
  | JBE = 212
  /// Jump if Condition Is Met (Jump short if CX register is 0).
  | JCXZ = 213
  /// Jump if Condition Is Met (Jump short if ECX register is 0).
  | JECXZ = 214
  /// Jump if Condition Is Met (Jump short if greater, ZF=0 and SF=OF).
  | JG = 215
  /// Jump if Condition Is Met (Jump short if less, SF≠OF).
  | JL = 216
  /// Jump if Condition Is Met (Jump short if less or equal, ZF=1 or SF≠OF).
  | JLE = 217
  /// Far jmp.
  | JMPFar = 218
  /// Near jmp.
  | JMPNear = 219
  /// Jump if Condition Is Met (Jump near if not below, CF=0).
  | JNB = 220
  /// Jump if Condition Is Met (Jump near if not less, SF=OF).
  | JNL = 221
  /// Jump if Condition Is Met (Jump near if not overflow, OF=0).
  | JNO = 222
  /// Jump if Condition Is Met (Jump near if not parity, PF=0).
  | JNP = 223
  /// Jump if Condition Is Met (Jump near if not sign, SF=0).
  | JNS = 224
  /// Jump if Condition Is Met (Jump near if not zero, ZF=0).
  | JNZ = 225
  /// Jump if Condition Is Met (Jump near if overflow, OF=1).
  | JO = 226
  /// Jump if Condition Is Met (Jump near if parity, PF=1).
  | JP = 227
  /// Jump if Condition Is Met (Jump short if RCX register is 0).
  | JRCXZ = 228
  /// Jump if Condition Is Met (Jump short if sign, SF=1).
  | JS = 229
  /// Jump if Condition Is Met (Jump short if zero, ZF=1).
  | JZ = 230
  /// Load Status Flags into AH Register.
  | LAHF = 231
  /// Load Access Rights Byte.
  | LAR = 232
  /// Load Unaligned Integer 128 Bits.
  | LDDQU = 233
  /// Load MXCSR Register.
  | LDMXCSR = 234
  /// Load Far Pointer (DS).
  | LDS = 235
  /// Load Effective Address.
  | LEA = 236
  /// High Level Procedure Exit.
  | LEAVE = 237
  /// Load Far Pointer (ES).
  | LES = 238
  /// Load Fence.
  | LFENCE = 239
  /// Load Far Pointer (FS).
  | LFS = 240
  /// Load GlobalDescriptor Table Register.
  | LGDT = 241
  /// Load Far Pointer (GS).
  | LGS = 242
  /// Load Interrupt Descriptor Table Register.
  | LIDT = 243
  /// Load Local Descriptor Table Register.
  | LLDT = 244
  /// Load Machine Status Word.
  | LMSW = 245
  /// Load String (byte).
  | LODSB = 246
  /// Load String (doubleword).
  | LODSD = 247
  /// Load String (quadword).
  | LODSQ = 248
  /// Load String (word).
  | LODSW = 249
  /// Loop According to ECX Counter (count ≠ 0).
  | LOOP = 250
  /// Loop According to ECX Counter (count ≠ 0 and ZF = 1).
  | LOOPE = 251
  /// Loop According to ECX Counter (count ≠ 0 and ZF = 0).
  | LOOPNE = 252
  /// Load Segment Limit.
  | LSL = 253
  /// Load Far Pointer (SS).
  | LSS = 254
  /// Load Task Register.
  | LTR = 255
  /// the Number of Leading Zero Bits.
  | LZCNT = 256
  /// Return Maximum Packed Double-Precision Floating-Point Values.
  | MAXPD = 257
  /// Return Maximum Packed Single-Precision Floating-Point Values.
  | MAXPS = 258
  /// Return Maximum Scalar Double-Precision Floating-Point Values.
  | MAXSD = 259
  /// Return Maximum Scalar Single-Precision Floating-Point Values.
  | MAXSS = 260
  /// Memory Fence.
  | MFENCE = 261
  /// Return Minimum Packed Double-Precision Floating-Point Values.
  | MINPD = 262
  /// Return Minimum Packed Single-Precision Floating-Point Values.
  | MINPS = 263
  /// Return Minimum Scalar Double-Precision Floating-Point Values.
  | MINSD = 264
  /// Return Minimum Scalar Single-Precision Floating-Point Values.
  | MINSS = 265
  /// Set Up Monitor Address.
  | MONITOR = 266
  /// MOV.
  | MOV = 267
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | MOVAPD = 268
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | MOVAPS = 269
  /// Move Data After Swapping Bytes.
  | MOVBE = 270
  /// Move Doubleword.
  | MOVD = 271
  /// Move One Double-FP and Duplicate.
  | MOVDDUP = 272
  /// Move Quadword from XMM to MMX Technology Register.
  | MOVDQ2Q = 273
  /// Move Aligned Double Quadword.
  | MOVDQA = 274
  /// Move Unaligned Double Quadword.
  | MOVDQU = 275
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | MOVHLPS = 276
  /// Move High Packed Double-Precision Floating-Point Value.
  | MOVHPD = 277
  /// Move High Packed Single-Precision Floating-Point Values.
  | MOVHPS = 278
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | MOVLHPS = 279
  /// Move Low Packed Double-Precision Floating-Point Value.
  | MOVLPD = 280
  /// Move Low Packed Single-Precision Floating-Point Values.
  | MOVLPS = 281
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | MOVMSKPD = 282
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | MOVMSKPS = 283
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQ = 284
  /// Store Doubleword Using Non-Temporal Hint.
  | MOVNTI = 285
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPD = 286
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPS = 287
  /// Store of Quadword Using Non-Temporal Hint.
  | MOVNTQ = 288
  /// Move Quadword.
  | MOVQ = 289
  /// Move Quadword from MMX Technology to XMM Register.
  | MOVQ2DQ = 290
  /// Move Data from String to String (byte).
  | MOVSB = 291
  /// Move Data from String to String (doubleword).
  | MOVSD = 292
  /// Move Packed Single-FP High and Duplicate.
  | MOVSHDUP = 293
  /// Move Packed Single-FP Low and Duplicate.
  | MOVSLDUP = 294
  /// Move Data from String to String (quadword).
  | MOVSQ = 295
  /// Move Scalar Single-Precision Floating-Point Values.
  | MOVSS = 296
  /// Move Data from String to String (word).
  | MOVSW = 297
  /// Move with Sign-Extension.
  | MOVSX = 298
  /// Move with Sign-Extension (doubleword to quadword).
  | MOVSXD = 299
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | MOVUPD = 300
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | MOVUPS = 301
  /// Move with Zero-Extend.
  | MOVZX = 302
  /// Unsigned Multiply.
  | MUL = 303
  /// Multiply Packed Double-Precision Floating-Point Values.
  | MULPD = 304
  /// Multiply Packed Single-Precision Floating-Point Values.
  | MULPS = 305
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | MULSD = 306
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | MULSS = 307
  /// Unsigned multiply without affecting arithmetic flags.
  | MULX = 308
  /// Monitor Wait.
  | MWAIT = 309
  /// Two's Complement Negation.
  | NEG = 310
  /// No Operation.
  | NOP = 311
  /// One's Complement Negation.
  | NOT = 312
  /// Logical Inclusive OR.
  | OR = 313
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | ORPD = 314
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | ORPS = 315
  /// Output to Port.
  | OUT = 316
  /// Output String to Port.
  | OUTS = 317
  /// Output String to Port (byte).
  | OUTSB = 318
  /// Output String to Port (doubleword).
  | OUTSD = 319
  /// Output String to Port (word).
  | OUTSW = 320
  /// Computes the absolute value of each signed byte data element.
  | PABSB = 321
  /// Computes the absolute value of each signed 32-bit data element.
  | PABSD = 322
  /// Computes the absolute value of each signed 16-bit data element.
  | PABSW = 323
  /// Pack with Signed Saturation.
  | PACKSSDW = 324
  /// Pack with Signed Saturation.
  | PACKSSWB = 325
  /// Pack with Unsigned Saturation.
  | PACKUSDW = 326
  /// Pack with Unsigned Saturation.
  | PACKUSWB = 327
  /// Add Packed byte Integers.
  | PADDB = 328
  /// Add Packed Doubleword Integers.
  | PADDD = 329
  /// Add Packed Quadword Integers.
  | PADDQ = 330
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | PADDSB = 331
  /// Add Packed Signed Integers with Signed Saturation (word).
  | PADDSW = 332
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | PADDUSB = 333
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | PADDUSW = 334
  /// Add Packed word Integers.
  | PADDW = 335
  /// Packed Align Right.
  | PALIGNR = 336
  /// Logical AND.
  | PAND = 337
  /// Logical AND NOT.
  | PANDN = 338
  /// Spin Loop Hint.
  | PAUSE = 339
  /// Average Packed Integers (byte).
  | PAVGB = 340
  /// Average Packed Integers (word).
  | PAVGW = 341
  /// Compare Packed Data for Equal (byte).
  | PCMPEQB = 342
  /// Compare Packed Data for Equal (doubleword).
  | PCMPEQD = 343
  /// Compare Packed Data for Equal (quadword).
  | PCMPEQQ = 344
  /// Compare packed words for equal.
  | PCMPEQW = 345
  /// Packed Compare Explicit Length Strings, Return Index.
  | PCMPESTRI = 346
  /// Packed Compare Explicit Length Strings, Return Mask.
  | PCMPESTRM = 347
  /// Compare Packed Signed Integers for Greater Than (byte).
  | PCMPGTB = 348
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | PCMPGTD = 349
  /// Performs logical compare of greater-than on packed integer quadwords.
  | PCMPGTQ = 350
  /// Compare Packed Signed Integers for Greater Than (word).
  | PCMPGTW = 351
  /// Packed Compare Implicit Length Strings, Return Index.
  | PCMPISTRI = 352
  /// Packed Compare Implicit Length Strings, Return Mask.
  | PCMPISTRM = 353
  /// Extract Word.
  | PEXTRW = 354
  /// Packed Horizontal Add.
  | PHADDD = 355
  /// Packed Horizontal Add and Saturate.
  | PHADDSW = 356
  /// Packed Horizontal Add.
  | PHADDW = 357
  /// Packed Horizontal Word Minimum.
  | PHMINPOSUW = 358
  /// Packed Horizontal Subtract.
  | PHSUBD = 359
  /// Packed Horizontal Subtract and Saturate.
  | PHSUBSW = 360
  /// Packed Horizontal Subtract.
  | PHSUBW = 361
  /// Insert Byte.
  | PINSRB = 362
  /// Insert Word.
  | PINSRW = 363
  /// Multiply and Add Packed Integers.
  | PMADDWD = 364
  /// Compare packed signed byte integers.
  | PMAXSB = 365
  /// Compare packed signed dword integers.
  | PMAXSD = 366
  /// Maximum of Packed Signed Word Integers.
  | PMAXSW = 367
  /// Maximum of Packed Unsigned Byte Integers.
  | PMAXUB = 368
  /// Compare packed unsigned dword integers.
  | PMAXUD = 369
  /// Compare packed unsigned word integers.
  | PMAXUW = 370
  /// Minimum of Packed Signed Byte Integers.
  | PMINSB = 371
  /// Compare packed signed dword integers.
  | PMINSD = 372
  /// Minimum of Packed Signed Word Integers.
  | PMINSW = 373
  /// Minimum of Packed Unsigned Byte Integers.
  | PMINUB = 374
  /// Minimum of Packed Dword Integers.
  | PMINUD = 375
  /// Compare packed unsigned word integers.
  | PMINUW = 376
  /// Move Byte Mask.
  | PMOVMSKB = 377
  /// Packed Move with Sign Extend.
  | PMOVSXBD = 378
  /// Packed Move with Sign Extend.
  | PMOVSXBQ = 379
  /// Packed Move with Sign Extend.
  | PMOVSXBW = 380
  /// Packed Move with Sign Extend.
  | PMOVSXDQ = 381
  /// Packed Move with Sign Extend.
  | PMOVSXWD = 382
  /// Packed Move with Sign Extend.
  | PMOVSXWQ = 383
  /// Packed Move with Zero Extend.
  | PMOVZXBD = 384
  /// Packed Move with Zero Extend.
  | PMOVZXBQ = 385
  /// Packed Move with Zero Extend.
  | PMOVZXBW = 386
  /// Packed Move with Zero Extend.
  | PMOVZXDQ = 387
  /// Packed Move with Zero Extend.
  | PMOVZXWD = 388
  /// Packed Move with Zero Extend.
  | PMOVZXWQ = 389
  /// Multiply Packed Doubleword Integers.
  | PMULDQ = 390
  /// Packed Multiply High with Round and Scale.
  | PMULHRSW = 391
  /// Multiply Packed Unsigned Integers and Store High Result.
  | PMULHUW = 392
  /// Multiply Packed Signed Integers and Store High Result.
  | PMULHW = 393
  /// Multiply Packed Integers and Store Low Result.
  | PMULLD = 394
  /// Multiply Packed Signed Integers and Store Low Result.
  | PMULLW = 395
  /// Multiply Packed Unsigned Doubleword Integers.
  | PMULUDQ = 396
  /// Pop a Value from the Stack.
  | POP = 397
  /// Pop All General-Purpose Registers (word).
  | POPA = 398
  /// Pop All General-Purpose Registers (doubleword).
  | POPAD = 399
  /// Return the Count of Number of Bits Set to 1.
  | POPCNT = 400
  /// Pop Stack into EFLAGS Register (lower 16bits EFLAGS).
  | POPF = 401
  /// Pop Stack into EFLAGS Register (EFLAGS).
  | POPFD = 402
  /// Pop Stack into EFLAGS Register (RFLAGS).
  | POPFQ = 403
  /// Bitwise Logical OR.
  | POR = 404
  /// Prefetch Data Into Caches (using NTA hint).
  | PREFETCHNTA = 405
  /// Prefetch Data Into Caches (using T0 hint).
  | PREFETCHT0 = 406
  /// Prefetch Data Into Caches (using T1 hint).
  | PREFETCHT1 = 407
  /// Prefetch Data Into Caches (using T2 hint).
  | PREFETCHT2 = 408
  /// Prefetch Data into Caches in Anticipation of a Write.
  | PREFETCHW = 409
  /// Prefetch Vector Data Into Caches with Intent to Write and T1 Hint.
  | PREFETCHWT1 = 410
  /// Compute Sum of Absolute Differences.
  | PSADBW = 411
  /// Packed Shuffle Bytes.
  | PSHUFB = 412
  /// Shuffle Packed Doublewords.
  | PSHUFD = 413
  /// Shuffle Packed High Words.
  | PSHUFHW = 414
  /// Shuffle Packed Low Words.
  | PSHUFLW = 415
  /// Shuffle Packed Words.
  | PSHUFW = 416
  /// Packed Sign Byte.
  | PSIGNB = 417
  /// Packed Sign Doubleword.
  | PSIGND = 418
  /// Packed Sign Word.
  | PSIGNW = 419
  /// Shift Packed Data Left Logical (doubleword).
  | PSLLD = 420
  /// Shift Double Quadword Left Logical.
  | PSLLDQ = 421
  /// Shift Packed Data Left Logical (quadword).
  | PSLLQ = 422
  /// Shift Packed Data Left Logical (word).
  | PSLLW = 423
  /// Shift Packed Data Right Arithmetic (doubleword).
  | PSRAD = 424
  /// Shift Packed Data Right Arithmetic (word).
  | PSRAW = 425
  /// Shift Packed Data Right Logical (doubleword).
  | PSRLD = 426
  /// Shift Double Quadword Right Logical.
  | PSRLDQ = 427
  /// Shift Packed Data Right Logical (quadword).
  | PSRLQ = 428
  /// Shift Packed Data Right Logical (word).
  | PSRLW = 429
  /// Subtract Packed Integers (byte).
  | PSUBB = 430
  /// Subtract Packed Integers (doubleword).
  | PSUBD = 431
  /// Subtract Packed Integers (quadword).
  | PSUBQ = 432
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | PSUBSB = 433
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | PSUBSW = 434
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | PSUBUSB = 435
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | PSUBUSW = 436
  /// Subtract Packed Integers (word).
  | PSUBW = 437
  /// Logical Compare.
  | PTEST = 438
  /// Unpack High Data.
  | PUNPCKHBW = 439
  /// Unpack High Data.
  | PUNPCKHDQ = 440
  /// Unpack High Data.
  | PUNPCKHQDQ = 441
  /// Unpack High Data.
  | PUNPCKHWD = 442
  /// Unpack Low Data.
  | PUNPCKLBW = 443
  /// Unpack Low Data.
  | PUNPCKLDQ = 444
  /// Unpack Low Data.
  | PUNPCKLQDQ = 445
  /// Unpack Low Data.
  | PUNPCKLWD = 446
  /// Push Word, Doubleword or Quadword Onto the Stack.
  | PUSH = 447
  /// Push All General-Purpose Registers (word).
  | PUSHA = 448
  /// Push All General-Purpose Registers (doubleword).
  | PUSHAD = 449
  /// Push EFLAGS Register onto the Stack (16bits of EFLAGS).
  | PUSHF = 450
  /// Push EFLAGS Register onto the Stack (EFLAGS).
  | PUSHFD = 451
  /// Push EFLAGS Register onto the Stack (RFLAGS).
  | PUSHFQ = 452
  /// Logical Exclusive OR.
  | PXOR = 453
  /// Rotate x bits (CF, r/m(x)) left once.
  | RCL = 454
  /// Rotate x bits (CF, r/m(x)) right once.
  | RCR = 455
  /// Read FS Segment Base.
  | RDFSBASE = 456
  /// Read GS Segment Base.
  | RDGSBASE = 457
  /// Read from Model Specific Register.
  | RDMSR = 458
  /// Read Protection Key Rights for User Pages.
  | RDPKRU = 459
  /// Read Performance-Monitoring Counters.
  | RDPMC = 460
  /// Read Random Number.
  | RDRAND = 461
  /// Read Random SEED.
  | RDSEED = 462
  /// Read Time-Stamp Counter.
  | RDTSC = 463
  /// Read Time-Stamp Counter and Processor ID.
  | RDTSCP = 464
  /// Far return.
  | RETFar = 465
  /// Far return w/ immediate.
  | RETFarImm = 466
  /// Near return.
  | RETNear = 467
  /// Near return w/ immediate .
  | RETNearImm = 468
  /// Rotate x bits r/m(x) left once..
  | ROL = 469
  /// Rotate x bits r/m(x) right once.
  | ROR = 470
  /// Rotate right without affecting arithmetic flags.
  | RORX = 471
  /// Round Scalar Double Precision Floating-Point Values.
  | ROUNDSD = 472
  /// Resume from System Management Mode.
  | RSM = 473
  /// Store AH into Flags.
  | SAHF = 474
  /// Shift.
  | SAR = 475
  /// Shift arithmetic right.
  | SARX = 476
  /// Integer Subtraction with Borrow.
  | SBB = 477
  /// Scan String (byte).
  | SCASB = 478
  /// Scan String (doubleword).
  | SCASD = 479
  /// Scan String (quadword).
  | SCASQ = 480
  /// Scan String (word).
  | SCASW = 481
  /// Set byte if above (CF=0 and ZF=0).
  | SETA = 482
  /// Set byte if below (CF=1).
  | SETB = 483
  /// Set byte if below or equal (CF=1 or ZF=1).
  | SETBE = 484
  /// Set byte if greater (ZF=0 and SF=OF)..
  | SETG = 485
  /// Set byte if less (SF≠ OF).
  | SETL = 486
  /// Set byte if less or equal (ZF=1 or SF≠ OF).
  | SETLE = 487
  /// Set byte if not below (CF=0).
  | SETNB = 488
  /// Set byte if not less (SF=OF).
  | SETNL = 489
  /// Set byte if not overflow (OF=0).
  | SETNO = 490
  /// Set byte if not parity (PF=0).
  | SETNP = 491
  /// Set byte if not sign (SF=0).
  | SETNS = 492
  /// Set byte if not zero (ZF=0).
  | SETNZ = 493
  /// Set byte if overflow (OF=1).
  | SETO = 494
  /// Set byte if parity (PF=1).
  | SETP = 495
  /// Set byte if sign (SF=1).
  | SETS = 496
  /// Set byte if sign (ZF=1).
  | SETZ = 497
  /// Store Fence.
  | SFENCE = 498
  /// Store Global Descriptor Table Register.
  | SGDT = 499
  /// Shift.
  | SHL = 500
  /// Double Precision Shift Left.
  | SHLD = 501
  /// Shift logic left.
  | SHLX = 502
  /// Shift.
  | SHR = 503
  /// Double Precision Shift Right.
  | SHRD = 504
  /// Shift logic right.
  | SHRX = 505
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | SHUFPD = 506
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | SHUFPS = 507
  /// Store Interrupt Descriptor Table Register.
  | SIDT = 508
  /// Store Local Descriptor Table Register.
  | SLDT = 509
  /// Store Machine Status Word.
  | SMSW = 510
  /// Compute packed square roots of packed double-precision FP values.
  | SQRTPD = 511
  /// Compute square roots of packed single-precision floating-point values.
  | SQRTPS = 512
  /// Compute scalar square root of scalar double-precision floating-point values.
  | SQRTSD = 513
  /// Compute square root of scalar single-precision floating-point values.
  | SQRTSS = 514
  /// Set AC Flag in EFLAGS Register.
  | STAC = 515
  /// Set Carry Flag.
  | STC = 516
  /// Set Direction Flag.
  | STD = 517
  /// Set Interrupt Flag.
  | STI = 518
  /// Store MXCSR Register State.
  | STMXCSR = 519
  /// Store String (store AL).
  | STOSB = 520
  /// Store String (store EAX).
  | STOSD = 521
  /// Store String (store RAX).
  | STOSQ = 522
  /// Store String (store AX).
  | STOSW = 523
  /// Store Task Register.
  | STR = 524
  /// Subtract.
  | SUB = 525
  /// Subtract Packed Double-Precision Floating-Point Values.
  | SUBPD = 526
  /// Subtract Packed Single-Precision Floating-Point Values.
  | SUBPS = 527
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | SUBSD = 528
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | SUBSS = 529
  /// Swap GS Base Register.
  | SWAPGS = 530
  /// Fast System Call.
  | SYSCALL = 531
  /// Fast System Call.
  | SYSENTER = 532
  /// Fast Return from Fast System Call.
  | SYSEXIT = 533
  /// Return From Fast System Call.
  | SYSRET = 534
  /// Logical Compare.
  | TEST = 535
  /// Count the Number of Trailing Zero Bits.
  | TZCNT = 536
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | UCOMISD = 537
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | UCOMISS = 538
  /// Undefined Instruction (Raise invalid opcode exception).
  | UD2 = 539
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | UNPCKHPD = 540
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | UNPCKHPS = 541
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | UNPCKLPD = 542
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | UNPCKLPS = 543
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPD = 544
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPS = 545
  /// Add Scalar Double-Precision Floating-Point Values.
  | VADDSD = 546
  /// Add Scalar Single-Precision Floating-Point Values.
  | VADDSS = 547
  /// Bitwise Logical AND of Packed Double-Precision Floating-Point Values.
  | VANDNPD = 548
  /// Bitwise Logical AND of Packed Single-Precision Floating-Point Values.
  | VANDNPS = 549
  /// Bitwise Logical AND NOT of Packed Double-Precision Floating-Point Values.
  | VANDPD = 550
  /// Bitwise Logical AND NOT of Packed Single-Precision Floating-Point Values.
  | VANDPS = 551
  /// Broadcast 128 bits of int data in mem to low and high 128-bits in ymm1.
  | VBROADCASTI128 = 552
  /// Broadcast Floating-Point Data.
  | VBROADCASTSS = 553
  /// Compare Scalar Ordered Double-Precision FP Values and Set EFLAGS.
  | VCOMISD = 554
  /// Compare Scalar Ordered Single-Precision FP Values and Set EFLAGS.
  | VCOMISS = 555
  /// Convert Scalar Double-Precision FP Value to Integer.
  | VCVTSD2SI = 556
  /// Convert Dword Integer to Scalar Double-Precision FP Value.
  | VCVTSI2SD = 557
  /// Convert Dword Integer to Scalar Single-Precision FP Value.
  | VCVTSI2SS = 558
  /// Convert Scalar Single-Precision FP Value to Dword Integer.
  | VCVTSS2SI = 559
  /// Convert with Truncation Scalar Double-Precision FP Value to Signed.
  | VCVTTSD2SI = 560
  /// Convert with Truncation Scalar Single-Precision FP Value to Dword Integer.
  | VCVTTSS2SI = 561
  /// Divide Packed Double-Precision Floating-Point Values.
  | VDIVPD = 562
  /// Divide Packed Single-Precision Floating-Point Values.
  | VDIVPS = 563
  /// Divide Scalar Double-Precision Floating-Point Values.
  | VDIVSD = 564
  /// Divide Scalar Single-Precision Floating-Point Values.
  | VDIVSS = 565
  /// Verify a Segment for Reading.
  | VERR = 566
  /// Verify a Segment for Writing.
  | VERW = 567
  /// Insert Packed Integer Values.
  | VINSERTI128 = 568
  /// Load Unaligned Integer 128 Bits.
  | VLDDQU = 569
  /// Call to VM Monitor.
  | VMCALL = 570
  /// Clear Virtual-Machine Control Structure.
  | VMCLEAR = 571
  /// Invoke VM function.
  | VMFUNC = 572
  /// Launch Virtual Machine.
  | VMLAUNCH = 573
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | VMOVAPD = 574
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | VMOVAPS = 575
  /// Move Doubleword.
  | VMOVD = 576
  /// Move One Double-FP and Duplicate.
  | VMOVDDUP = 577
  /// Move Aligned Double Quadword.
  | VMOVDQA = 578
  /// Move Aligned Double Quadword.
  | VMOVDQA32 = 579
  /// Move Aligned Double Quadword.
  | VMOVDQA64 = 580
  /// Move Unaligned Double Quadword.
  | VMOVDQU = 581
  /// Move Unaligned Double Quadword.
  | VMOVDQU32 = 582
  /// Move Unaligned Double Quadword.
  | VMOVDQU64 = 583
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | VMOVHLPS = 584
  /// Move High Packed Double-Precision Floating-Point Value.
  | VMOVHPD = 585
  /// Move High Packed Single-Precision Floating-Point Values.
  | VMOVHPS = 586
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | VMOVLHPS = 587
  /// Move Low Packed Double-Precision Floating-Point Value.
  | VMOVLPD = 588
  /// Move Low Packed Single-Precision Floating-Point Values.
  | VMOVLPS = 589
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | VMOVMSKPD = 590
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | VMOVMSKPS = 591
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | VMOVNTDQ = 592
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPD = 593
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPS = 594
  /// Move Quadword.
  | VMOVQ = 595
  /// Move Data from String to String (doubleword)..
  | VMOVSD = 596
  /// Move Packed Single-FP High and Duplicate.
  | VMOVSHDUP = 597
  /// Move Packed Single-FP Low and Duplicate.
  | VMOVSLDUP = 598
  /// Move Scalar Single-Precision Floating-Point Values.
  | VMOVSS = 599
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | VMOVUPD = 600
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | VMOVUPS = 601
  /// Load Pointer to Virtual-Machine Control Structure.
  | VMPTRLD = 602
  /// Store Pointer to Virtual-Machine Control Structure.
  | VMPTRST = 603
  /// Resume Virtual Machine.
  | VMRESUME = 604
  /// Multiply Packed Double-Precision Floating-Point Values.
  | VMULPD = 605
  /// Multiply Packed Single-Precision Floating-Point Values.
  | VMULPS = 606
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | VMULSD = 607
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | VMULSS = 608
  /// Leave VMX Operation.
  | VMXOFF = 609
  /// Enter VMX Operation.
  | VMXON = 610
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | VORPD = 611
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | VORPS = 612
  /// Packed Absolute Value (byte).
  | VPABSB = 613
  /// Packed Absolute Value (dword).
  | VPABSD = 614
  /// Packed Absolute Value (word).
  | VPABSW = 615
  /// Pack with Signed Saturation.
  | VPACKSSDW = 616
  /// Pack with Signed Saturation.
  | VPACKSSWB = 617
  /// Pack with Unsigned Saturation.
  | VPACKUSDW = 618
  /// Pack with Unsigned Saturation.
  | VPACKUSWB = 619
  /// Add Packed byte Integers.
  | VPADDB = 620
  /// Add Packed Doubleword Integers.
  | VPADDD = 621
  /// Add Packed Quadword Integers.
  | VPADDQ = 622
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | VPADDSB = 623
  /// Add Packed Signed Integers with Signed Saturation (word).
  | VPADDSW = 624
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPADDUSB = 625
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | VPADDUSW = 626
  /// Add Packed word Integers.
  | VPADDW = 627
  /// Packed Align Right.
  | VPALIGNR = 628
  /// Logical AND.
  | VPAND = 629
  /// Logical AND NOT.
  | VPANDN = 630
  /// Average Packed Integers (byte).
  | VPAVGB = 631
  /// Average Packed Integers (word).
  | VPAVGW = 632
  /// Broadcast Integer Data.
  | VPBROADCASTB = 633
  /// Compare Packed Data for Equal (byte).
  | VPCMPEQB = 634
  /// Compare Packed Data for Equal (doubleword).
  | VPCMPEQD = 635
  /// Compare Packed Data for Equal (quadword).
  | VPCMPEQQ = 636
  /// Compare Packed Data for Equal (word).
  | VPCMPEQW = 637
  /// Packed Compare Explicit Length Strings, Return Index.
  | VPCMPESTRI = 638
  /// Packed Compare Explicit Length Strings, Return Mask.
  | VPCMPESTRM = 639
  /// Compare Packed Signed Integers for Greater Than (byte).
  | VPCMPGTB = 640
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | VPCMPGTD = 641
  /// Compare Packed Data for Greater Than (qword).
  | VPCMPGTQ = 642
  /// Compare Packed Signed Integers for Greater Than (word).
  | VPCMPGTW = 643
  /// Packed Compare Implicit Length Strings, Return Index.
  | VPCMPISTRI = 644
  /// Packed Compare Implicit Length Strings, Return Mask.
  | VPCMPISTRM = 645
  /// Extract Word.
  | VPEXTRW = 646
  /// Packed Horizontal Add (32-bit).
  | VPHADDD = 647
  /// Packed Horizontal Add and Saturate (16-bit).
  | VPHADDSW = 648
  /// Packed Horizontal Add (16-bit).
  | VPHADDW = 649
  /// Packed Horizontal Word Minimum.
  | VPHMINPOSUW = 650
  /// Packed Horizontal Subtract (32-bit).
  | VPHSUBD = 651
  /// Packed Horizontal Subtract and Saturate (16-bit)
  | VPHSUBSW = 652
  /// Packed Horizontal Subtract (16-bit).
  | VPHSUBW = 653
  /// Insert Byte.
  | VPINSRB = 654
  /// Insert Word.
  | VPINSRW = 655
  /// Multiply and Add Packed Integers.
  | VPMADDWD = 656
  /// Maximum of Packed Signed Integers (byte).
  | VPMAXSB = 657
  /// Maximum of Packed Signed Integers (dword).
  | VPMAXSD = 658
  /// Maximum of Packed Signed Word Integers.
  | VPMAXSW = 659
  /// Maximum of Packed Unsigned Byte Integers.
  | VPMAXUB = 660
  /// Maximum of Packed Unsigned Integers (dword).
  | VPMAXUD = 661
  /// Maximum of Packed Unsigned Integers (word).
  | VPMAXUW = 662
  /// Minimum of Packed Signed Integers (byte).
  | VPMINSB = 663
  /// Minimum of Packed Signed Integers (dword).
  | VPMINSD = 664
  /// Minimum of Packed Signed Word Integers.
  | VPMINSW = 665
  /// Minimum of Packed Unsigned Byte Integers.
  | VPMINUB = 666
  /// Minimum of Packed Dword Integers.
  | VPMINUD = 667
  /// Minimum of Packed Unsigned Integers (word).
  | VPMINUW = 668
  /// Move Byte Mask.
  | VPMOVMSKB = 669
  /// Packed Move with Sign Extend (8-bit to 32-bit).
  | VPMOVSXBD = 670
  /// Packed Move with Sign Extend (8-bit to 64-bit).
  | VPMOVSXBQ = 671
  /// Packed Move with Sign Extend (8-bit to 16-bit).
  | VPMOVSXBW = 672
  /// Packed Move with Sign Extend (32-bit to 64-bit).
  | VPMOVSXDQ = 673
  /// Packed Move with Sign Extend (16-bit to 32-bit).
  | VPMOVSXWD = 674
  /// Packed Move with Sign Extend (16-bit to 64-bit).
  | VPMOVSXWQ = 675
  /// Packed Move with Zero Extend (8-bit to 32-bit).
  | VPMOVZXBD = 676
  /// Packed Move with Zero Extend (8-bit to 64-bit).
  | VPMOVZXBQ = 677
  /// Packed Move with Zero Extend (8-bit to 16-bit).
  | VPMOVZXBW = 678
  /// Packed Move with Zero Extend (32-bit to 64-bit).
  | VPMOVZXDQ = 679
  /// Packed Move with Zero Extend (16-bit to 32-bit).
  | VPMOVZXWD = 680
  /// Packed Move with Zero Extend (16-bit to 64-bit).
  | VPMOVZXWQ = 681
  /// Multiply Packed Doubleword Integers.
  | VPMULDQ = 682
  /// Packed Multiply High with Round and Scale.
  | VPMULHRSW = 683
  /// Multiply Packed Unsigned Integers and Store High Result.
  | VPMULHUW = 684
  /// Multiply Packed Signed Integers and Store High Result.
  | VPMULHW = 685
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLD = 686
  /// Multiply Packed Signed Integers and Store Low Result.
  | VPMULLW = 687
  /// Multiply Packed Unsigned Doubleword Integers.
  | VPMULUDQ = 688
  /// Bitwise Logical OR.
  | VPOR = 689
  /// Compute Sum of Absolute Differences.
  | VPSADBW = 690
  /// Packed Shuffle Bytes.
  | VPSHUFB = 691
  /// Shuffle Packed Doublewords.
  | VPSHUFD = 692
  /// Shuffle Packed High Words.
  | VPSHUFHW = 693
  /// Shuffle Packed Low Words.
  | VPSHUFLW = 694
  /// Packed SIGN (byte).
  | VPSIGNB = 695
  /// Packed SIGN (doubleword).
  | VPSIGND = 696
  /// Packed SIGN (word).
  | VPSIGNW = 697
  /// Shift Packed Data Left Logical (doubleword).
  | VPSLLD = 698
  /// Shift Double Quadword Left Logical.
  | VPSLLDQ = 699
  /// Shift Packed Data Left Logical (quadword).
  | VPSLLQ = 700
  /// Shift Packed Data Left Logical (word).
  | VPSLLW = 701
  /// Shift Packed Data Right Arithmetic (doubleword).
  | VPSRAD = 702
  /// Shift Packed Data Right Arithmetic (word).
  | VPSRAW = 703
  /// Shift Packed Data Right Logical (doubleword).
  | VPSRLD = 704
  /// Shift Double Quadword Right Logical.
  | VPSRLDQ = 705
  /// Shift Packed Data Right Logical (quadword).
  | VPSRLQ = 706
  /// Shift Packed Data Right Logical (word).
  | VPSRLW = 707
  /// Subtract Packed Integers (byte).
  | VPSUBB = 708
  /// Subtract Packed Integers (doubleword).
  | VPSUBD = 709
  /// Subtract Packed Integers (quadword).
  | VPSUBQ = 710
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | VPSUBSB = 711
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | VPSUBSW = 712
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPSUBUSB = 713
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | VPSUBUSW = 714
  /// Subtract Packed Integers (word).
  | VPSUBW = 715
  /// Logical Compare.
  | VPTEST = 716
  /// Unpack High Data.
  | VPUNPCKHBW = 717
  /// Unpack High Data.
  | VPUNPCKHDQ = 718
  /// Unpack High Data.
  | VPUNPCKHQDQ = 719
  /// Unpack High Data.
  | VPUNPCKHWD = 720
  /// Unpack Low Data.
  | VPUNPCKLBW = 721
  /// Unpack Low Data.
  | VPUNPCKLDQ = 722
  /// Unpack Low Data.
  | VPUNPCKLQDQ = 723
  /// Unpack Low Data.
  | VPUNPCKLWD = 724
  /// Logical Exclusive OR.
  | VPXOR = 725
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | VSHUFPD = 726
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | VSHUFPS = 727
  /// Compute packed square roots of packed double-precision FP values.
  | VSQRTPD = 728
  /// Compute square roots of packed single-precision floating-point values.
  | VSQRTPS = 729
  /// Compute scalar square root of scalar double-precision floating-point values.
  | VSQRTSD = 730
  /// Compute square root of scalar single-precision floating-point values.
  | VSQRTSS = 731
  /// Subtract Packed Double-Precision Floating-Point Values.
  | VSUBPD = 732
  /// Subtract Packed Single-Precision Floating-Point Values.
  | VSUBPS = 733
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | VSUBSD = 734
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | VSUBSS = 735
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | VUCOMISD = 736
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | VUCOMISS = 737
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | VUNPCKHPD = 738
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | VUNPCKHPS = 739
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | VUNPCKLPD = 740
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | VUNPCKLPS = 741
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | VXORPD = 742
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | VXORPS = 743
  /// Zero Upper Bits of YMM Registers.
  | VZEROUPPER = 744
  /// Wait.
  | WAIT = 745
  /// Write Back and Invalidate Cache.
  | WBINVD = 746
  /// Write FS Segment Base.
  | WRFSBASE = 747
  /// Write GS Segment Base.
  | WRGSBASE = 748
  /// Write to Model Specific Register.
  | WRMSR = 749
  /// Write Data to User Page Key Register.
  | WRPKRU = 750
  /// Transactional Abort.
  | XABORT = 751
  /// Exchange and Add.
  | XADD = 752
  /// Transactional Begin.
  | XBEGIN = 753
  /// Exchange Register/Memory with Register.
  | XCHG = 754
  /// Transactional End.
  | XEND = 755
  /// Value of Extended Control Register.
  | XGETBV = 756
  /// Table Look-up Translation.
  | XLATB = 757
  /// Logical Exclusive OR.
  | XOR = 758
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | XORPD = 759
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | XORPS = 760
  /// Restore Processor Extended States.
  | XRSTOR = 761
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS = 762
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS64 = 763
  /// Save Processor Extended States.
  | XSAVE = 764
  /// Save processor extended states with compaction to memory.
  | XSAVEC = 765
  /// Save processor extended states with compaction to memory.
  | XSAVEC64 = 766
  /// Save Processor Extended States Optimized.
  | XSAVEOPT = 767
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES = 768
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES64 = 769
  /// Set Extended Control Register.
  | XSETBV = 770
  /// Test If In Transactional Execution.
  | XTEST = 771
  /// Invalid Opcode.
  | InvalOP = 772

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
///
/// Internally, B2R2 represents OperandDesc as an integer as follows to speed up
/// the parsing process:
/// <code>
/// ODImmOne
/// +---------+-------------------------------------+
/// | 0 0 0 1 |           0 (12bit)                 |
/// +---------+-------------------------------------+
/// ODModeSize
/// +---------+-------------------------------------+
/// | 0 0 1 0 |    size (6bit)   |   mode (6bit)    |
/// +---------+-------------------------------------+
/// ODReg
/// +---------+-------------------------------------+
/// | 0 0 1 1 |       Register ID (12bit)           |
/// +---------+-------------------------------------+
/// ODRegGrp
/// +---------+------------+-----------+------------+
/// | 0 1 0 0 | size(6bit) | grp(3bit) | attr(3bit) |
/// +---------+------------+-----------+------------+
/// </code>
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
