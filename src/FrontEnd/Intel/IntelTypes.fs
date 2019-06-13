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
  /// Compare String Operands (byte).
  | CMPSB = 54
  /// Compare String Operands (dword).
  | CMPSD = 55
  /// Compare String Operands (quadword).
  | CMPSQ = 56
  /// Compare String Operands (word).
  | CMPSW = 57
  /// Compare and Exchange.
  | CMPXCHG = 58
  /// Compare and Exchange Bytes.
  | CMPXCHG16B = 59
  /// Compare and Exchange Bytes.
  | CMPXCHG8B = 60
  /// Compare Scalar Ordered Double-Precision FP Values and Set EFLAGS.
  | COMISD = 61
  /// Compare Scalar Ordered Single-Precision FP Values and Set EFLAGS.
  | COMISS = 62
  /// CPU Identification.
  | CPUID = 63
  /// Convert Quadword to Octaword.
  | CQO = 64
  /// Accumulate CRC32 Value.
  | CRC32 = 65
  /// Convert Packed Dword Integers to Packed Double-Precision FP Values.
  | CVTDQ2PD = 66
  /// Convert Packed Dword Integers to Packed Single-Precision FP Values.
  | CVTDQ2PS = 67
  /// Convert Packed Double-Precision FP Values to Packed Dword Integers.
  | CVTPD2DQ = 68
  /// Convert Packed Double-Precision FP Values to Packed Dword Integers.
  | CVTPD2PI = 69
  /// Convert Packed Double-Precision FP Values to Packed Single-Precision FP.
  | CVTPD2PS = 70
  /// Convert Packed Dword Integers to Packed Double-Precision FP Values.
  | CVTPI2PD = 71
  /// Convert Packed Dword Integers to Packed Single-Precision FP Values.
  | CVTPI2PS = 72
  /// Convert Packed Single-Precision FP Values to Packed Dword Integers.
  | CVTPS2DQ = 73
  /// Convert Packed Single-Precision FP Values to Packed Double-Precision FP.
  | CVTPS2PD = 74
  /// Convert Packed Single-Precision FP Values to Packed Dword Integers.
  | CVTPS2PI = 75
  /// Convert Scalar Double-Precision FP Value to Integer.
  | CVTSD2SI = 76
  /// Convert Scalar Double-Precision FP Value to Scalar Single-Precision FP.
  | CVTSD2SS = 77
  /// Convert Dword Integer to Scalar Double-Precision FP Value.
  | CVTSI2SD = 78
  /// Convert Dword Integer to Scalar Single-Precision FP Value.
  | CVTSI2SS = 79
  /// Convert Scalar Single-Precision FP Value to Scalar Double-Precision FP.
  | CVTSS2SD = 80
  /// Convert Scalar Single-Precision FP Value to Dword Integer.
  | CVTSS2SI = 81
  /// Convert with Truncation Packed Double-Precision FP Values to Packed Dword.
  | CVTTPD2DQ = 82
  /// Convert with Truncation Packed Double-Precision FP Values to Packed Dword.
  | CVTTPD2PI = 83
  /// Convert with Truncation Packed Single-Precision FP Values to Packed Dword.
  | CVTTPS2DQ = 84
  /// Convert with Truncation Packed Single-Precision FP Values to Packed Dword.
  | CVTTPS2PI = 85
  /// Convert with Truncation Scalar Double-Precision FP Value to Signed.
  | CVTTSD2SI = 86
  /// Convert with Truncation Scalar Single-Precision FP Value to Dword Integer.
  | CVTTSS2SI = 87
  /// Convert Word to Doubleword.
  | CWD = 88
  /// Convert Word to Doubleword.
  | CWDE = 89
  /// Decimal Adjust AL after Addition.
  | DAA = 90
  /// Decimal Adjust AL after Subtraction.
  | DAS = 91
  /// Decrement by 1.
  | DEC = 92
  /// Unsigned Divide.
  | DIV = 93
  /// Divide Packed Double-Precision Floating-Point Values.
  | DIVPD = 94
  /// Divide Packed Single-Precision Floating-Point Values.
  | DIVPS = 95
  /// Divide Scalar Double-Precision Floating-Point Values.
  | DIVSD = 96
  /// Divide Scalar Single-Precision Floating-Point Values.
  | DIVSS = 97
  /// Make Stack Frame for Procedure Parameters.
  | ENTER = 98
  /// Compute 2x-1.
  | F2XM1 = 99
  /// Absolute Value.
  | FABS = 100
  /// Add.
  | FADD = 101
  /// Add and pop the register stack.
  | FADDP = 102
  /// Load Binary Coded Decimal.
  | FBLD = 103
  /// Store BCD Integer and Pop.
  | FBSTP = 104
  /// Change Sign.
  | FCHS = 105
  /// Clear Exceptions.
  | FCLEX = 106
  /// Floating-Point Conditional Move (if below (CF=1)).
  | FCMOVB = 107
  /// Floating-Point Conditional Move (if below or equal (CF=1 or ZF=1)).
  | FCMOVBE = 108
  /// Floating-Point Conditional Move (if equal (ZF=1)).
  | FCMOVE = 109
  /// Floating-Point Conditional Move (if not below (CF=0)).
  | FCMOVNB = 110
  /// Floating-Point Conditional Move (if not below or equal (CF=0 and ZF=0)).
  | FCMOVNBE = 111
  /// Floating-Point Conditional Move (if not equal (ZF=0)).
  | FCMOVNE = 112
  /// Floating-Point Conditional Move (if not unordered (PF=0)).
  | FCMOVNU = 113
  /// Floating-Point Conditional Move (if unordered (PF=1)).
  | FCMOVU = 114
  /// Compare Floating Point Values.
  | FCOM = 115
  /// Compare Floating Point Values and Set EFLAGS.
  | FCOMI = 116
  /// Compare Floating Point Values and Set EFLAGS.
  | FCOMIP = 117
  /// Compare Floating Point Values and pop register stack.
  | FCOMP = 118
  /// Compare Floating Point Values and pop register stack twice.
  | FCOMPP = 119
  /// Cosine.
  | FCOS = 120
  /// Decrement Stack-Top Pointer.
  | FDECSTP = 121
  /// Divide.
  | FDIV = 122
  /// Divide and pop the register stack.
  | FDIVP = 123
  /// Reverse Divide.
  | FDIVR = 124
  /// Reverse Divide and pop the register stack.
  | FDIVRP = 125
  /// Free Floating-Point Register.
  | FFREE = 126
  /// Add.
  | FIADD = 127
  /// Compare Integer.
  | FICOM = 128
  /// Compare Integer and pop the register stack.
  | FICOMP = 129
  /// Divide.
  | FIDIV = 130
  /// Reverse Divide.
  | FIDIVR = 131
  /// Load Integer.
  | FILD = 132
  /// Multiply.
  | FIMUL = 133
  /// Increment Stack-Top Pointer.
  | FINCSTP = 134
  /// Initialize Floating-Point Unit.
  | FINIT = 135
  /// Store Integer.
  | FIST = 136
  /// Store Integer and pop the register stack.
  | FISTP = 137
  /// Store Integer with Truncation.
  | FISTTP = 138
  /// Subtract.
  | FISUB = 139
  /// Reverse Subtract.
  | FISUBR = 140
  /// Load Floating Point Value.
  | FLD = 141
  /// Load Constant (Push +1.0 onto the FPU register stack).
  | FLD1 = 142
  /// Load x87 FPU Control Word.
  | FLDCW = 143
  /// Load x87 FPU Environment.
  | FLDENV = 144
  /// Load Constant (Push log2e onto the FPU register stack).
  | FLDL2E = 145
  /// Load Constant (Push log210 onto the FPU register stack).
  | FLDL2T = 146
  /// Load Constant (Push log102 onto the FPU register stack).
  | FLDLG2 = 147
  /// Load Constant (Push loge2 onto the FPU register stack).
  | FLDLN2 = 148
  /// Load Constant (Push Pi onto the FPU register stack).
  | FLDPI = 149
  /// Load Constant (Push +0.0 onto the FPU register stack).
  | FLDZ = 150
  /// Multiply.
  | FMUL = 151
  /// Multiply and pop the register stack.
  | FMULP = 152
  /// No Operation.
  | FNOP = 153
  /// Partial Arctangent.
  | FPATAN = 154
  /// Partial Remainder.
  | FPREM = 155
  /// Partial Remainder.
  | FPREM1 = 156
  /// Partial Tangent.
  | FPTAN = 157
  /// Round to Integer.
  | FRNDINT = 158
  /// Restore x87 FPU State.
  | FRSTOR = 159
  /// Store x87 FPU State.
  | FSAVE = 160
  /// Scale.
  | FSCALE = 161
  /// Sine.
  | FSIN = 162
  /// Sine and Cosine.
  | FSINCOS = 163
  /// Square Root.
  | FSQRT = 164
  /// Store Floating Point Value.
  | FST = 165
  /// Store x87 FPU Control Word.
  | FSTCW = 166
  /// Store x87 FPU Environment.
  | FSTENV = 167
  /// Store Floating Point Value.
  | FSTP = 168
  /// Store x87 FPU Status Word.
  | FSTSW = 169
  /// Subtract.
  | FSUB = 170
  /// Subtract and pop register stack.
  | FSUBP = 171
  /// Reverse Subtract.
  | FSUBR = 172
  /// Reverse Subtract and pop register stack.
  | FSUBRP = 173
  /// TEST.
  | FTST = 174
  /// Unordered Compare Floating Point Values.
  | FUCOM = 175
  /// Compare Floating Point Values and Set EFLAGS.
  | FUCOMI = 176
  /// Compare Floating Point Values and Set EFLAGS and pop register stack.
  | FUCOMIP = 177
  /// Unordered Compare Floating Point Values.
  | FUCOMP = 178
  /// Unordered Compare Floating Point Values.
  | FUCOMPP = 179
  /// Examine ModR/M.
  | FXAM = 180
  /// Exchange Register Contents.
  | FXCH = 181
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR = 182
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR64 = 183
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE = 184
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE64 = 185
  /// Extract Exponent and Significand.
  | FXTRACT = 186
  /// compute y * log2x.
  | FYL2X = 187
  /// compute y * log2(x+1).
  | FYL2XP1 = 188
  /// GETSEC.
  | GETSEC = 189
  /// Halt.
  | HLT = 190
  /// Signed Divide.
  | IDIV = 191
  /// Signed Multiply.
  | IMUL = 192
  /// Input from Port.
  | IN = 193
  /// Increment by 1.
  | INC = 194
  /// Input from Port to String.
  | INS = 195
  /// Input from Port to String (byte).
  | INSB = 196
  /// Input from Port to String (doubleword).
  | INSD = 197
  /// Input from Port to String (word).
  | INSW = 198
  /// Call to Interrupt (Interrupt vector specified by immediate byte).
  | INT = 199
  /// Call to Interrupt (Interrupt 3?trap to debugger).
  | INT3 = 200
  /// Call to Interrupt (InteInterrupt 4?if overflow flag is 1).
  | INTO = 201
  /// Invalidate Internal Caches.
  | INVD = 202
  /// Invalidate TLB Entries.
  | INVLPG = 203
  /// Interrupt return (32-bit operand size).
  | IRETD = 204
  /// Interrupt return (64-bit operand size).
  | IRETQ = 205
  /// Interrupt return (16-bit operand size).
  | IRETW = 206
  /// Jump if Condition Is Met (Jump short if above, CF=0 and ZF=0).
  | JA = 207
  /// Jump if Condition Is Met (Jump short if below, CF=1).
  | JB = 208
  /// Jump if Condition Is Met (Jump short if below or equal, CF=1 or ZF).
  | JBE = 209
  /// Jump if Condition Is Met (Jump short if CX register is 0).
  | JCXZ = 210
  /// Jump if Condition Is Met (Jump short if ECX register is 0).
  | JECXZ = 211
  /// Jump if Condition Is Met (Jump short if greater, ZF=0 and SF=OF).
  | JG = 212
  /// Jump if Condition Is Met (Jump short if less, SF≠OF).
  | JL = 213
  /// Jump if Condition Is Met (Jump short if less or equal, ZF=1 or SF≠OF).
  | JLE = 214
  /// Far jmp.
  | JMPFar = 215
  /// Near jmp.
  | JMPNear = 216
  /// Jump if Condition Is Met (Jump near if not below, CF=0).
  | JNB = 217
  /// Jump if Condition Is Met (Jump near if not less, SF=OF).
  | JNL = 218
  /// Jump if Condition Is Met (Jump near if not overflow, OF=0).
  | JNO = 219
  /// Jump if Condition Is Met (Jump near if not parity, PF=0).
  | JNP = 220
  /// Jump if Condition Is Met (Jump near if not sign, SF=0).
  | JNS = 221
  /// Jump if Condition Is Met (Jump near if not zero, ZF=0).
  | JNZ = 222
  /// Jump if Condition Is Met (Jump near if overflow, OF=1).
  | JO = 223
  /// Jump if Condition Is Met (Jump near if parity, PF=1).
  | JP = 224
  /// Jump if Condition Is Met (Jump short if RCX register is 0).
  | JRCXZ = 225
  /// Jump if Condition Is Met (Jump short if sign, SF=1).
  | JS = 226
  /// Jump if Condition Is Met (Jump short if zero, ZF=1).
  | JZ = 227
  /// Load Status Flags into AH Register.
  | LAHF = 228
  /// Load Access Rights Byte.
  | LAR = 229
  /// Load Unaligned Integer 128 Bits.
  | LDDQU = 230
  /// Load MXCSR Register.
  | LDMXCSR = 231
  /// Load Far Pointer (DS).
  | LDS = 232
  /// Load Effective Address.
  | LEA = 233
  /// High Level Procedure Exit.
  | LEAVE = 234
  /// Load Far Pointer (ES).
  | LES = 235
  /// Load Fence.
  | LFENCE = 236
  /// Load Far Pointer (FS).
  | LFS = 237
  /// Load GlobalDescriptor Table Register.
  | LGDT = 238
  /// Load Far Pointer (GS).
  | LGS = 239
  /// Load Interrupt Descriptor Table Register.
  | LIDT = 240
  /// Load Local Descriptor Table Register.
  | LLDT = 241
  /// Load Machine Status Word.
  | LMSW = 242
  /// Load String (byte).
  | LODSB = 243
  /// Load String (doubleword).
  | LODSD = 244
  /// Load String (quadword).
  | LODSQ = 245
  /// Load String (word).
  | LODSW = 246
  /// Loop According to ECX Counter (count ≠ 0).
  | LOOP = 247
  /// Loop According to ECX Counter (count ≠ 0 and ZF = 1).
  | LOOPE = 248
  /// Loop According to ECX Counter (count ≠ 0 and ZF = 0).
  | LOOPNE = 249
  /// Load Segment Limit.
  | LSL = 250
  /// Load Far Pointer (SS).
  | LSS = 251
  /// Load Task Register.
  | LTR = 252
  /// the Number of Leading Zero Bits.
  | LZCNT = 253
  /// Return Maximum Packed Double-Precision Floating-Point Values.
  | MAXPD = 254
  /// Return Maximum Packed Single-Precision Floating-Point Values.
  | MAXPS = 255
  /// Return Maximum Scalar Double-Precision Floating-Point Values.
  | MAXSD = 256
  /// Return Maximum Scalar Single-Precision Floating-Point Values.
  | MAXSS = 257
  /// Memory Fence.
  | MFENCE = 258
  /// Return Minimum Packed Double-Precision Floating-Point Values.
  | MINPD = 259
  /// Return Minimum Packed Single-Precision Floating-Point Values.
  | MINPS = 260
  /// Return Minimum Scalar Double-Precision Floating-Point Values.
  | MINSD = 261
  /// Return Minimum Scalar Single-Precision Floating-Point Values.
  | MINSS = 262
  /// Set Up Monitor Address.
  | MONITOR = 263
  /// MOV.
  | MOV = 264
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | MOVAPD = 265
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | MOVAPS = 266
  /// Move Data After Swapping Bytes.
  | MOVBE = 267
  /// Move Doubleword.
  | MOVD = 268
  /// Move One Double-FP and Duplicate.
  | MOVDDUP = 269
  /// Move Quadword from XMM to MMX Technology Register.
  | MOVDQ2Q = 270
  /// Move Aligned Double Quadword.
  | MOVDQA = 271
  /// Move Unaligned Double Quadword.
  | MOVDQU = 272
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | MOVHLPS = 273
  /// Move High Packed Double-Precision Floating-Point Value.
  | MOVHPD = 274
  /// Move High Packed Single-Precision Floating-Point Values.
  | MOVHPS = 275
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | MOVLHPS = 276
  /// Move Low Packed Double-Precision Floating-Point Value.
  | MOVLPD = 277
  /// Move Low Packed Single-Precision Floating-Point Values.
  | MOVLPS = 278
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | MOVMSKPD = 279
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | MOVMSKPS = 280
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQ = 281
  /// Store Doubleword Using Non-Temporal Hint.
  | MOVNTI = 282
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPD = 283
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPS = 284
  /// Store of Quadword Using Non-Temporal Hint.
  | MOVNTQ = 285
  /// Move Quadword.
  | MOVQ = 286
  /// Move Quadword from MMX Technology to XMM Register.
  | MOVQ2DQ = 287
  /// Move Data from String to String (byte).
  | MOVSB = 288
  /// Move Data from String to String (doubleword).
  | MOVSD = 289
  /// Move Packed Single-FP High and Duplicate.
  | MOVSHDUP = 290
  /// Move Packed Single-FP Low and Duplicate.
  | MOVSLDUP = 291
  /// Move Data from String to String (quadword).
  | MOVSQ = 292
  /// Move Scalar Single-Precision Floating-Point Values.
  | MOVSS = 293
  /// Move Data from String to String (word).
  | MOVSW = 294
  /// Move with Sign-Extension.
  | MOVSX = 295
  /// Move with Sign-Extension (doubleword to quadword).
  | MOVSXD = 296
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | MOVUPD = 297
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | MOVUPS = 298
  /// Move with Zero-Extend.
  | MOVZX = 299
  /// Unsigned Multiply.
  | MUL = 300
  /// Multiply Packed Double-Precision Floating-Point Values.
  | MULPD = 301
  /// Multiply Packed Single-Precision Floating-Point Values.
  | MULPS = 302
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | MULSD = 303
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | MULSS = 304
  /// Unsigned multiply without affecting arithmetic flags.
  | MULX = 305
  /// Monitor Wait.
  | MWAIT = 306
  /// Two's Complement Negation.
  | NEG = 307
  /// No Operation.
  | NOP = 308
  /// One's Complement Negation.
  | NOT = 309
  /// Logical Inclusive OR.
  | OR = 310
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | ORPD = 311
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | ORPS = 312
  /// Output to Port.
  | OUT = 313
  /// Output String to Port.
  | OUTS = 314
  /// Output String to Port (byte).
  | OUTSB = 315
  /// Output String to Port (doubleword).
  | OUTSD = 316
  /// Output String to Port (word).
  | OUTSW = 317
  /// Computes the absolute value of each signed byte data element.
  | PABSB = 318
  /// Computes the absolute value of each signed 32-bit data element.
  | PABSD = 319
  /// Computes the absolute value of each signed 16-bit data element.
  | PABSW = 320
  /// Pack with Signed Saturation.
  | PACKSSDW = 321
  /// Pack with Signed Saturation.
  | PACKSSWB = 322
  /// Pack with Unsigned Saturation.
  | PACKUSDW = 323
  /// Pack with Unsigned Saturation.
  | PACKUSWB = 324
  /// Add Packed byte Integers.
  | PADDB = 325
  /// Add Packed Doubleword Integers.
  | PADDD = 326
  /// Add Packed Quadword Integers.
  | PADDQ = 327
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | PADDSB = 328
  /// Add Packed Signed Integers with Signed Saturation (word).
  | PADDSW = 329
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | PADDUSB = 330
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | PADDUSW = 331
  /// Add Packed word Integers.
  | PADDW = 332
  /// Packed Align Right.
  | PALIGNR = 333
  /// Logical AND.
  | PAND = 334
  /// Logical AND NOT.
  | PANDN = 335
  /// Spin Loop Hint.
  | PAUSE = 336
  /// Average Packed Integers (byte).
  | PAVGB = 337
  /// Average Packed Integers (word).
  | PAVGW = 338
  /// Compare Packed Data for Equal (byte).
  | PCMPEQB = 339
  /// Compare Packed Data for Equal (doubleword).
  | PCMPEQD = 340
  /// Compare Packed Data for Equal (quadword).
  | PCMPEQQ = 341
  /// Compare packed words for equal.
  | PCMPEQW = 342
  /// Packed Compare Explicit Length Strings, Return Index.
  | PCMPESTRI = 343
  /// Packed Compare Explicit Length Strings, Return Mask.
  | PCMPESTRM = 344
  /// Compare Packed Signed Integers for Greater Than (byte).
  | PCMPGTB = 345
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | PCMPGTD = 346
  /// Performs logical compare of greater-than on packed integer quadwords.
  | PCMPGTQ = 347
  /// Compare Packed Signed Integers for Greater Than (word).
  | PCMPGTW = 348
  /// Packed Compare Implicit Length Strings, Return Index.
  | PCMPISTRI = 349
  /// Packed Compare Implicit Length Strings, Return Mask.
  | PCMPISTRM = 350
  /// Extract Word.
  | PEXTRW = 351
  /// Packed Horizontal Add.
  | PHADDD = 352
  /// Packed Horizontal Add and Saturate.
  | PHADDSW = 353
  /// Packed Horizontal Add.
  | PHADDW = 354
  /// Packed Horizontal Word Minimum.
  | PHMINPOSUW = 355
  /// Packed Horizontal Subtract.
  | PHSUBD = 356
  /// Packed Horizontal Subtract and Saturate.
  | PHSUBSW = 357
  /// Packed Horizontal Subtract.
  | PHSUBW = 358
  /// Insert Byte.
  | PINSRB = 359
  /// Insert Word.
  | PINSRW = 360
  /// Multiply and Add Packed Integers.
  | PMADDWD = 361
  /// Compare packed signed byte integers.
  | PMAXSB = 362
  /// Compare packed signed dword integers.
  | PMAXSD = 363
  /// Maximum of Packed Signed Word Integers.
  | PMAXSW = 364
  /// Maximum of Packed Unsigned Byte Integers.
  | PMAXUB = 365
  /// Compare packed unsigned dword integers.
  | PMAXUD = 366
  /// Compare packed unsigned word integers.
  | PMAXUW = 367
  /// Minimum of Packed Signed Byte Integers.
  | PMINSB = 368
  /// Compare packed signed dword integers.
  | PMINSD = 369
  /// Minimum of Packed Signed Word Integers.
  | PMINSW = 370
  /// Minimum of Packed Unsigned Byte Integers.
  | PMINUB = 371
  /// Minimum of Packed Dword Integers.
  | PMINUD = 372
  /// Compare packed unsigned word integers.
  | PMINUW = 373
  /// Move Byte Mask.
  | PMOVMSKB = 374
  /// Packed Move with Sign Extend.
  | PMOVSXBD = 375
  /// Packed Move with Sign Extend.
  | PMOVSXBQ = 376
  /// Packed Move with Sign Extend.
  | PMOVSXBW = 377
  /// Packed Move with Sign Extend.
  | PMOVSXDQ = 378
  /// Packed Move with Sign Extend.
  | PMOVSXWD = 379
  /// Packed Move with Sign Extend.
  | PMOVSXWQ = 380
  /// Packed Move with Zero Extend.
  | PMOVZXBD = 381
  /// Packed Move with Zero Extend.
  | PMOVZXBQ = 382
  /// Packed Move with Zero Extend.
  | PMOVZXBW = 383
  /// Packed Move with Zero Extend.
  | PMOVZXDQ = 384
  /// Packed Move with Zero Extend.
  | PMOVZXWD = 385
  /// Packed Move with Zero Extend.
  | PMOVZXWQ = 386
  /// Multiply Packed Doubleword Integers.
  | PMULDQ = 387
  /// Packed Multiply High with Round and Scale.
  | PMULHRSW = 388
  /// Multiply Packed Unsigned Integers and Store High Result.
  | PMULHUW = 389
  /// Multiply Packed Signed Integers and Store High Result.
  | PMULHW = 390
  /// Multiply Packed Integers and Store Low Result.
  | PMULLD = 391
  /// Multiply Packed Signed Integers and Store Low Result.
  | PMULLW = 392
  /// Multiply Packed Unsigned Doubleword Integers.
  | PMULUDQ = 393
  /// Pop a Value from the Stack.
  | POP = 394
  /// Pop All General-Purpose Registers (word).
  | POPA = 395
  /// Pop All General-Purpose Registers (doubleword).
  | POPAD = 396
  /// Return the Count of Number of Bits Set to 1.
  | POPCNT = 397
  /// Pop Stack into EFLAGS Register (lower 16bits EFLAGS).
  | POPF = 398
  /// Pop Stack into EFLAGS Register (EFLAGS).
  | POPFD = 399
  /// Pop Stack into EFLAGS Register (RFLAGS).
  | POPFQ = 400
  /// Bitwise Logical OR.
  | POR = 401
  /// Prefetch Data Into Caches (using NTA hint).
  | PREFETCHNTA = 402
  /// Prefetch Data Into Caches (using T0 hint).
  | PREFETCHT0 = 403
  /// Prefetch Data Into Caches (using T1 hint).
  | PREFETCHT1 = 404
  /// Prefetch Data Into Caches (using T2 hint).
  | PREFETCHT2 = 405
  /// Prefetch Data into Caches in Anticipation of a Write.
  | PREFETCHW = 406
  /// Prefetch Vector Data Into Caches with Intent to Write and T1 Hint.
  | PREFETCHWT1 = 407
  /// Compute Sum of Absolute Differences.
  | PSADBW = 408
  /// Packed Shuffle Bytes.
  | PSHUFB = 409
  /// Shuffle Packed Doublewords.
  | PSHUFD = 410
  /// Shuffle Packed High Words.
  | PSHUFHW = 411
  /// Shuffle Packed Low Words.
  | PSHUFLW = 412
  /// Shuffle Packed Words.
  | PSHUFW = 413
  /// Packed Sign Byte.
  | PSIGNB = 414
  /// Packed Sign Doubleword.
  | PSIGND = 415
  /// Packed Sign Word.
  | PSIGNW = 416
  /// Shift Packed Data Left Logical (doubleword).
  | PSLLD = 417
  /// Shift Double Quadword Left Logical.
  | PSLLDQ = 418
  /// Shift Packed Data Left Logical (quadword).
  | PSLLQ = 419
  /// Shift Packed Data Left Logical (word).
  | PSLLW = 420
  /// Shift Packed Data Right Arithmetic (doubleword).
  | PSRAD = 421
  /// Shift Packed Data Right Arithmetic (word).
  | PSRAW = 422
  /// Shift Packed Data Right Logical (doubleword).
  | PSRLD = 423
  /// Shift Double Quadword Right Logical.
  | PSRLDQ = 424
  /// Shift Packed Data Right Logical (quadword).
  | PSRLQ = 425
  /// Shift Packed Data Right Logical (word).
  | PSRLW = 426
  /// Subtract Packed Integers (byte).
  | PSUBB = 427
  /// Subtract Packed Integers (doubleword).
  | PSUBD = 428
  /// Subtract Packed Integers (quadword).
  | PSUBQ = 429
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | PSUBSB = 430
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | PSUBSW = 431
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | PSUBUSB = 432
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | PSUBUSW = 433
  /// Subtract Packed Integers (word).
  | PSUBW = 434
  /// Logical Compare.
  | PTEST = 435
  /// Unpack High Data.
  | PUNPCKHBW = 436
  /// Unpack High Data.
  | PUNPCKHDQ = 437
  /// Unpack High Data.
  | PUNPCKHQDQ = 438
  /// Unpack High Data.
  | PUNPCKHWD = 439
  /// Unpack Low Data.
  | PUNPCKLBW = 440
  /// Unpack Low Data.
  | PUNPCKLDQ = 441
  /// Unpack Low Data.
  | PUNPCKLQDQ = 442
  /// Unpack Low Data.
  | PUNPCKLWD = 443
  /// Push Word, Doubleword or Quadword Onto the Stack.
  | PUSH = 444
  /// Push All General-Purpose Registers (word).
  | PUSHA = 445
  /// Push All General-Purpose Registers (doubleword).
  | PUSHAD = 446
  /// Push EFLAGS Register onto the Stack (16bits of EFLAGS).
  | PUSHF = 447
  /// Push EFLAGS Register onto the Stack (EFLAGS).
  | PUSHFD = 448
  /// Push EFLAGS Register onto the Stack (RFLAGS).
  | PUSHFQ = 449
  /// Logical Exclusive OR.
  | PXOR = 450
  /// Rotate x bits (CF, r/m(x)) left once.
  | RCL = 451
  /// Rotate x bits (CF, r/m(x)) right once.
  | RCR = 452
  /// Read FS Segment Base.
  | RDFSBASE = 453
  /// Read GS Segment Base.
  | RDGSBASE = 454
  /// Read from Model Specific Register.
  | RDMSR = 455
  /// Read Protection Key Rights for User Pages.
  | RDPKRU = 456
  /// Read Performance-Monitoring Counters.
  | RDPMC = 457
  /// Read Random Number.
  | RDRAND = 458
  /// Read Random SEED.
  | RDSEED = 459
  /// Read Time-Stamp Counter.
  | RDTSC = 460
  /// Read Time-Stamp Counter and Processor ID.
  | RDTSCP = 461
  /// Far return.
  | RETFar = 462
  /// Far return w/ immediate.
  | RETFarImm = 463
  /// Near return.
  | RETNear = 464
  /// Near return w/ immediate .
  | RETNearImm = 465
  /// Rotate x bits r/m(x) left once..
  | ROL = 466
  /// Rotate x bits r/m(x) right once.
  | ROR = 467
  /// Rotate right without affecting arithmetic flags.
  | RORX = 468
  /// Round Scalar Double Precision Floating-Point Values.
  | ROUNDSD = 469
  /// Resume from System Management Mode.
  | RSM = 470
  /// Store AH into Flags.
  | SAHF = 471
  /// Shift.
  | SAR = 472
  /// Shift arithmetic right.
  | SARX = 473
  /// Integer Subtraction with Borrow.
  | SBB = 474
  /// Scan String (byte).
  | SCASB = 475
  /// Scan String (doubleword).
  | SCASD = 476
  /// Scan String (quadword).
  | SCASQ = 477
  /// Scan String (word).
  | SCASW = 478
  /// Set byte if above (CF=0 and ZF=0).
  | SETA = 479
  /// Set byte if below (CF=1).
  | SETB = 480
  /// Set byte if below or equal (CF=1 or ZF=1).
  | SETBE = 481
  /// Set byte if greater (ZF=0 and SF=OF)..
  | SETG = 482
  /// Set byte if less (SF≠ OF).
  | SETL = 483
  /// Set byte if less or equal (ZF=1 or SF≠ OF).
  | SETLE = 484
  /// Set byte if not below (CF=0).
  | SETNB = 485
  /// Set byte if not less (SF=OF).
  | SETNL = 486
  /// Set byte if not overflow (OF=0).
  | SETNO = 487
  /// Set byte if not parity (PF=0).
  | SETNP = 488
  /// Set byte if not sign (SF=0).
  | SETNS = 489
  /// Set byte if not zero (ZF=0).
  | SETNZ = 490
  /// Set byte if overflow (OF=1).
  | SETO = 491
  /// Set byte if parity (PF=1).
  | SETP = 492
  /// Set byte if sign (SF=1).
  | SETS = 493
  /// Set byte if sign (ZF=1).
  | SETZ = 494
  /// Store Fence.
  | SFENCE = 495
  /// Store Global Descriptor Table Register.
  | SGDT = 496
  /// Shift.
  | SHL = 497
  /// Double Precision Shift Left.
  | SHLD = 498
  /// Shift logic left.
  | SHLX = 499
  /// Shift.
  | SHR = 500
  /// Double Precision Shift Right.
  | SHRD = 501
  /// Shift logic right.
  | SHRX = 502
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | SHUFPD = 503
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | SHUFPS = 504
  /// Store Interrupt Descriptor Table Register.
  | SIDT = 505
  /// Store Local Descriptor Table Register.
  | SLDT = 506
  /// Store Machine Status Word.
  | SMSW = 507
  /// Compute packed square roots of packed double-precision FP values.
  | SQRTPD = 508
  /// Compute square roots of packed single-precision floating-point values.
  | SQRTPS = 509
  /// Compute scalar square root of scalar double-precision floating-point values.
  | SQRTSD = 510
  /// Compute square root of scalar single-precision floating-point values.
  | SQRTSS = 511
  /// Set AC Flag in EFLAGS Register.
  | STAC = 512
  /// Set Carry Flag.
  | STC = 513
  /// Set Direction Flag.
  | STD = 514
  /// Set Interrupt Flag.
  | STI = 515
  /// Store MXCSR Register State.
  | STMXCSR = 516
  /// Store String (store AL).
  | STOSB = 517
  /// Store String (store EAX).
  | STOSD = 518
  /// Store String (store RAX).
  | STOSQ = 519
  /// Store String (store AX).
  | STOSW = 520
  /// Store Task Register.
  | STR = 521
  /// Subtract.
  | SUB = 522
  /// Subtract Packed Double-Precision Floating-Point Values.
  | SUBPD = 523
  /// Subtract Packed Single-Precision Floating-Point Values.
  | SUBPS = 524
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | SUBSD = 525
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | SUBSS = 526
  /// Swap GS Base Register.
  | SWAPGS = 527
  /// Fast System Call.
  | SYSCALL = 528
  /// Fast System Call.
  | SYSENTER = 529
  /// Fast Return from Fast System Call.
  | SYSEXIT = 530
  /// Return From Fast System Call.
  | SYSRET = 531
  /// Logical Compare.
  | TEST = 532
  /// Count the Number of Trailing Zero Bits.
  | TZCNT = 533
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | UCOMISD = 534
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | UCOMISS = 535
  /// Undefined Instruction (Raise invalid opcode exception).
  | UD2 = 536
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | UNPCKHPD = 537
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | UNPCKHPS = 538
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | UNPCKLPD = 539
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | UNPCKLPS = 540
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPD = 541
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPS = 542
  /// Add Scalar Double-Precision Floating-Point Values.
  | VADDSD = 543
  /// Add Scalar Single-Precision Floating-Point Values.
  | VADDSS = 544
  /// Bitwise Logical AND of Packed Double-Precision Floating-Point Values.
  | VANDNPD = 545
  /// Bitwise Logical AND of Packed Single-Precision Floating-Point Values.
  | VANDNPS = 546
  /// Bitwise Logical AND NOT of Packed Double-Precision Floating-Point Values.
  | VANDPD = 547
  /// Bitwise Logical AND NOT of Packed Single-Precision Floating-Point Values.
  | VANDPS = 548
  /// Broadcast 128 bits of int data in mem to low and high 128-bits in ymm1.
  | VBROADCASTI128 = 549
  /// Broadcast Floating-Point Data.
  | VBROADCASTSS = 550
  /// Compare Scalar Ordered Double-Precision FP Values and Set EFLAGS.
  | VCOMISD = 551
  /// Compare Scalar Ordered Single-Precision FP Values and Set EFLAGS.
  | VCOMISS = 552
  /// Convert Scalar Double-Precision FP Value to Integer.
  | VCVTSD2SI = 553
  /// Convert Dword Integer to Scalar Double-Precision FP Value.
  | VCVTSI2SD = 554
  /// Convert Dword Integer to Scalar Single-Precision FP Value.
  | VCVTSI2SS = 555
  /// Convert Scalar Single-Precision FP Value to Dword Integer.
  | VCVTSS2SI = 556
  /// Convert with Truncation Scalar Double-Precision FP Value to Signed.
  | VCVTTSD2SI = 557
  /// Convert with Truncation Scalar Single-Precision FP Value to Dword Integer.
  | VCVTTSS2SI = 558
  /// Divide Packed Double-Precision Floating-Point Values.
  | VDIVPD = 559
  /// Divide Packed Single-Precision Floating-Point Values.
  | VDIVPS = 560
  /// Divide Scalar Double-Precision Floating-Point Values.
  | VDIVSD = 561
  /// Divide Scalar Single-Precision Floating-Point Values.
  | VDIVSS = 562
  /// Verify a Segment for Reading.
  | VERR = 563
  /// Verify a Segment for Writing.
  | VERW = 564
  /// Insert Packed Integer Values.
  | VINSERTI128 = 565
  /// Load Unaligned Integer 128 Bits.
  | VLDDQU = 566
  /// Call to VM Monitor.
  | VMCALL = 567
  /// Clear Virtual-Machine Control Structure.
  | VMCLEAR = 568
  /// Invoke VM function.
  | VMFUNC = 569
  /// Launch Virtual Machine.
  | VMLAUNCH = 570
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | VMOVAPD = 571
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | VMOVAPS = 572
  /// Move Doubleword.
  | VMOVD = 573
  /// Move One Double-FP and Duplicate.
  | VMOVDDUP = 574
  /// Move Aligned Double Quadword.
  | VMOVDQA = 575
  /// Move Aligned Double Quadword.
  | VMOVDQA32 = 576
  /// Move Aligned Double Quadword.
  | VMOVDQA64 = 577
  /// Move Unaligned Double Quadword.
  | VMOVDQU = 578
  /// Move Unaligned Double Quadword.
  | VMOVDQU32 = 579
  /// Move Unaligned Double Quadword.
  | VMOVDQU64 = 580
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | VMOVHLPS = 581
  /// Move High Packed Double-Precision Floating-Point Value.
  | VMOVHPD = 582
  /// Move High Packed Single-Precision Floating-Point Values.
  | VMOVHPS = 583
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | VMOVLHPS = 584
  /// Move Low Packed Double-Precision Floating-Point Value.
  | VMOVLPD = 585
  /// Move Low Packed Single-Precision Floating-Point Values.
  | VMOVLPS = 586
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | VMOVMSKPD = 587
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | VMOVMSKPS = 588
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | VMOVNTDQ = 589
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPD = 590
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPS = 591
  /// Move Quadword.
  | VMOVQ = 592
  /// Move Data from String to String (doubleword)..
  | VMOVSD = 593
  /// Move Packed Single-FP High and Duplicate.
  | VMOVSHDUP = 594
  /// Move Packed Single-FP Low and Duplicate.
  | VMOVSLDUP = 595
  /// Move Scalar Single-Precision Floating-Point Values.
  | VMOVSS = 596
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | VMOVUPD = 597
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | VMOVUPS = 598
  /// Load Pointer to Virtual-Machine Control Structure.
  | VMPTRLD = 599
  /// Store Pointer to Virtual-Machine Control Structure.
  | VMPTRST = 600
  /// Resume Virtual Machine.
  | VMRESUME = 601
  /// Multiply Packed Double-Precision Floating-Point Values.
  | VMULPD = 602
  /// Multiply Packed Single-Precision Floating-Point Values.
  | VMULPS = 603
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | VMULSD = 604
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | VMULSS = 605
  /// Leave VMX Operation.
  | VMXOFF = 606
  /// Enter VMX Operation.
  | VMXON = 607
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | VORPD = 608
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | VORPS = 609
  /// Packed Absolute Value (byte).
  | VPABSB = 610
  /// Packed Absolute Value (dword).
  | VPABSD = 611
  /// Packed Absolute Value (word).
  | VPABSW = 612
  /// Pack with Signed Saturation.
  | VPACKSSDW = 613
  /// Pack with Signed Saturation.
  | VPACKSSWB = 614
  /// Pack with Unsigned Saturation.
  | VPACKUSDW = 615
  /// Pack with Unsigned Saturation.
  | VPACKUSWB = 616
  /// Add Packed byte Integers.
  | VPADDB = 617
  /// Add Packed Doubleword Integers.
  | VPADDD = 618
  /// Add Packed Quadword Integers.
  | VPADDQ = 619
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | VPADDSB = 620
  /// Add Packed Signed Integers with Signed Saturation (word).
  | VPADDSW = 621
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPADDUSB = 622
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | VPADDUSW = 623
  /// Add Packed word Integers.
  | VPADDW = 624
  /// Packed Align Right.
  | VPALIGNR = 625
  /// Logical AND.
  | VPAND = 626
  /// Logical AND NOT.
  | VPANDN = 627
  /// Average Packed Integers (byte).
  | VPAVGB = 628
  /// Average Packed Integers (word).
  | VPAVGW = 629
  /// Broadcast Integer Data.
  | VPBROADCASTB = 630
  /// Compare Packed Data for Equal (byte).
  | VPCMPEQB = 631
  /// Compare Packed Data for Equal (doubleword).
  | VPCMPEQD = 632
  /// Compare Packed Data for Equal (quadword).
  | VPCMPEQQ = 633
  /// Compare Packed Data for Equal (word).
  | VPCMPEQW = 634
  /// Packed Compare Explicit Length Strings, Return Index.
  | VPCMPESTRI = 635
  /// Packed Compare Explicit Length Strings, Return Mask.
  | VPCMPESTRM = 636
  /// Compare Packed Signed Integers for Greater Than (byte).
  | VPCMPGTB = 637
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | VPCMPGTD = 638
  /// Compare Packed Data for Greater Than (qword).
  | VPCMPGTQ = 639
  /// Compare Packed Signed Integers for Greater Than (word).
  | VPCMPGTW = 640
  /// Packed Compare Implicit Length Strings, Return Index.
  | VPCMPISTRI = 641
  /// Packed Compare Implicit Length Strings, Return Mask.
  | VPCMPISTRM = 642
  /// Extract Word.
  | VPEXTRW = 643
  /// Packed Horizontal Add (32-bit).
  | VPHADDD = 644
  /// Packed Horizontal Add and Saturate (16-bit).
  | VPHADDSW = 645
  /// Packed Horizontal Add (16-bit).
  | VPHADDW = 646
  /// Packed Horizontal Word Minimum.
  | VPHMINPOSUW = 647
  /// Packed Horizontal Subtract (32-bit).
  | VPHSUBD = 648
  /// Packed Horizontal Subtract and Saturate (16-bit)
  | VPHSUBSW = 649
  /// Packed Horizontal Subtract (16-bit).
  | VPHSUBW = 650
  /// Insert Byte.
  | VPINSRB = 651
  /// Insert Word.
  | VPINSRW = 652
  /// Multiply and Add Packed Integers.
  | VPMADDWD = 653
  /// Maximum of Packed Signed Integers (byte).
  | VPMAXSB = 654
  /// Maximum of Packed Signed Integers (dword).
  | VPMAXSD = 655
  /// Maximum of Packed Signed Word Integers.
  | VPMAXSW = 656
  /// Maximum of Packed Unsigned Byte Integers.
  | VPMAXUB = 657
  /// Maximum of Packed Unsigned Integers (dword).
  | VPMAXUD = 658
  /// Maximum of Packed Unsigned Integers (word).
  | VPMAXUW = 659
  /// Minimum of Packed Signed Integers (byte).
  | VPMINSB = 660
  /// Minimum of Packed Signed Integers (dword).
  | VPMINSD = 661
  /// Minimum of Packed Signed Word Integers.
  | VPMINSW = 662
  /// Minimum of Packed Unsigned Byte Integers.
  | VPMINUB = 663
  /// Minimum of Packed Dword Integers.
  | VPMINUD = 664
  /// Minimum of Packed Unsigned Integers (word).
  | VPMINUW = 665
  /// Move Byte Mask.
  | VPMOVMSKB = 666
  /// Packed Move with Sign Extend (8-bit to 32-bit).
  | VPMOVSXBD = 667
  /// Packed Move with Sign Extend (8-bit to 64-bit).
  | VPMOVSXBQ = 668
  /// Packed Move with Sign Extend (8-bit to 16-bit).
  | VPMOVSXBW = 669
  /// Packed Move with Sign Extend (32-bit to 64-bit).
  | VPMOVSXDQ = 670
  /// Packed Move with Sign Extend (16-bit to 32-bit).
  | VPMOVSXWD = 671
  /// Packed Move with Sign Extend (16-bit to 64-bit).
  | VPMOVSXWQ = 672
  /// Packed Move with Zero Extend (8-bit to 32-bit).
  | VPMOVZXBD = 673
  /// Packed Move with Zero Extend (8-bit to 64-bit).
  | VPMOVZXBQ = 674
  /// Packed Move with Zero Extend (8-bit to 16-bit).
  | VPMOVZXBW = 675
  /// Packed Move with Zero Extend (32-bit to 64-bit).
  | VPMOVZXDQ = 676
  /// Packed Move with Zero Extend (16-bit to 32-bit).
  | VPMOVZXWD = 677
  /// Packed Move with Zero Extend (16-bit to 64-bit).
  | VPMOVZXWQ = 678
  /// Multiply Packed Doubleword Integers.
  | VPMULDQ = 679
  /// Packed Multiply High with Round and Scale.
  | VPMULHRSW = 680
  /// Multiply Packed Unsigned Integers and Store High Result.
  | VPMULHUW = 681
  /// Multiply Packed Signed Integers and Store High Result.
  | VPMULHW = 682
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLD = 683
  /// Multiply Packed Signed Integers and Store Low Result.
  | VPMULLW = 684
  /// Multiply Packed Unsigned Doubleword Integers.
  | VPMULUDQ = 685
  /// Bitwise Logical OR.
  | VPOR = 686
  /// Compute Sum of Absolute Differences.
  | VPSADBW = 687
  /// Packed Shuffle Bytes.
  | VPSHUFB = 688
  /// Shuffle Packed Doublewords.
  | VPSHUFD = 689
  /// Shuffle Packed High Words.
  | VPSHUFHW = 690
  /// Shuffle Packed Low Words.
  | VPSHUFLW = 691
  /// Packed SIGN (byte).
  | VPSIGNB = 692
  /// Packed SIGN (doubleword).
  | VPSIGND = 693
  /// Packed SIGN (word).
  | VPSIGNW = 694
  /// Shift Packed Data Left Logical (doubleword).
  | VPSLLD = 695
  /// Shift Double Quadword Left Logical.
  | VPSLLDQ = 696
  /// Shift Packed Data Left Logical (quadword).
  | VPSLLQ = 697
  /// Shift Packed Data Left Logical (word).
  | VPSLLW = 698
  /// Shift Packed Data Right Arithmetic (doubleword).
  | VPSRAD = 699
  /// Shift Packed Data Right Arithmetic (word).
  | VPSRAW = 700
  /// Shift Packed Data Right Logical (doubleword).
  | VPSRLD = 701
  /// Shift Double Quadword Right Logical.
  | VPSRLDQ = 702
  /// Shift Packed Data Right Logical (quadword).
  | VPSRLQ = 703
  /// Shift Packed Data Right Logical (word).
  | VPSRLW = 704
  /// Subtract Packed Integers (byte).
  | VPSUBB = 705
  /// Subtract Packed Integers (doubleword).
  | VPSUBD = 706
  /// Subtract Packed Integers (quadword).
  | VPSUBQ = 707
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | VPSUBSB = 708
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | VPSUBSW = 709
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPSUBUSB = 710
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | VPSUBUSW = 711
  /// Subtract Packed Integers (word).
  | VPSUBW = 712
  /// Logical Compare.
  | VPTEST = 713
  /// Unpack High Data.
  | VPUNPCKHBW = 714
  /// Unpack High Data.
  | VPUNPCKHDQ = 715
  /// Unpack High Data.
  | VPUNPCKHQDQ = 716
  /// Unpack High Data.
  | VPUNPCKHWD = 717
  /// Unpack Low Data.
  | VPUNPCKLBW = 718
  /// Unpack Low Data.
  | VPUNPCKLDQ = 719
  /// Unpack Low Data.
  | VPUNPCKLQDQ = 720
  /// Unpack Low Data.
  | VPUNPCKLWD = 721
  /// Logical Exclusive OR.
  | VPXOR = 722
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | VSHUFPD = 723
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | VSHUFPS = 724
  /// Compute packed square roots of packed double-precision FP values.
  | VSQRTPD = 725
  /// Compute square roots of packed single-precision floating-point values.
  | VSQRTPS = 726
  /// Compute scalar square root of scalar double-precision floating-point values.
  | VSQRTSD = 727
  /// Compute square root of scalar single-precision floating-point values.
  | VSQRTSS = 728
  /// Subtract Packed Double-Precision Floating-Point Values.
  | VSUBPD = 729
  /// Subtract Packed Single-Precision Floating-Point Values.
  | VSUBPS = 730
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | VSUBSD = 731
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | VSUBSS = 732
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | VUCOMISD = 733
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | VUCOMISS = 734
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | VUNPCKHPD = 735
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | VUNPCKHPS = 736
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | VUNPCKLPD = 737
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | VUNPCKLPS = 738
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | VXORPD = 739
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | VXORPS = 740
  /// Zero Upper Bits of YMM Registers.
  | VZEROUPPER = 741
  /// Wait.
  | WAIT = 742
  /// Write Back and Invalidate Cache.
  | WBINVD = 743
  /// Write FS Segment Base.
  | WRFSBASE = 744
  /// Write GS Segment Base.
  | WRGSBASE = 745
  /// Write to Model Specific Register.
  | WRMSR = 746
  /// Write Data to User Page Key Register.
  | WRPKRU = 747
  /// Transactional Abort.
  | XABORT = 748
  /// Exchange and Add.
  | XADD = 749
  /// Transactional Begin.
  | XBEGIN = 750
  /// Exchange Register/Memory with Register.
  | XCHG = 751
  /// Transactional End.
  | XEND = 752
  /// Value of Extended Control Register.
  | XGETBV = 753
  /// Table Look-up Translation.
  | XLATB = 754
  /// Logical Exclusive OR.
  | XOR = 755
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | XORPD = 756
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | XORPS = 757
  /// Restore Processor Extended States.
  | XRSTOR = 758
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS = 759
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS64 = 760
  /// Save Processor Extended States.
  | XSAVE = 761
  /// Save processor extended states with compaction to memory.
  | XSAVEC = 762
  /// Save processor extended states with compaction to memory.
  | XSAVEC64 = 763
  /// Save Processor Extended States Optimized.
  | XSAVEOPT = 764
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES = 765
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES64 = 766
  /// Set Extended Control Register.
  | XSETBV = 767
  /// Test If In Transactional Execution.
  | XTEST = 768
  /// Invalid Opcode.
  | InvalOP = 769

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
