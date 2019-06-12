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
  /// Monitor Wait.
  | MWAIT = 305
  /// Two's Complement Negation.
  | NEG = 306
  /// No Operation.
  | NOP = 307
  /// One's Complement Negation.
  | NOT = 308
  /// Logical Inclusive OR.
  | OR = 309
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | ORPD = 310
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | ORPS = 311
  /// Output to Port.
  | OUT = 312
  /// Output String to Port.
  | OUTS = 313
  /// Output String to Port (byte).
  | OUTSB = 314
  /// Output String to Port (doubleword).
  | OUTSD = 315
  /// Output String to Port (word).
  | OUTSW = 316
  /// Computes the absolute value of each signed byte data element.
  | PABSB = 317
  /// Computes the absolute value of each signed 32-bit data element.
  | PABSD = 318
  /// Computes the absolute value of each signed 16-bit data element.
  | PABSW = 319
  /// Pack with Signed Saturation.
  | PACKSSDW = 320
  /// Pack with Signed Saturation.
  | PACKSSWB = 321
  /// Pack with Unsigned Saturation.
  | PACKUSDW = 322
  /// Pack with Unsigned Saturation.
  | PACKUSWB = 323
  /// Add Packed byte Integers.
  | PADDB = 324
  /// Add Packed Doubleword Integers.
  | PADDD = 325
  /// Add Packed Quadword Integers.
  | PADDQ = 326
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | PADDSB = 327
  /// Add Packed Signed Integers with Signed Saturation (word).
  | PADDSW = 328
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | PADDUSB = 329
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | PADDUSW = 330
  /// Add Packed word Integers.
  | PADDW = 331
  /// Packed Align Right.
  | PALIGNR = 332
  /// Logical AND.
  | PAND = 333
  /// Logical AND NOT.
  | PANDN = 334
  /// Spin Loop Hint.
  | PAUSE = 335
  /// Average Packed Integers (byte).
  | PAVGB = 336
  /// Average Packed Integers (word).
  | PAVGW = 337
  /// Compare Packed Data for Equal (byte).
  | PCMPEQB = 338
  /// Compare Packed Data for Equal (doubleword).
  | PCMPEQD = 339
  /// Compare Packed Data for Equal (quadword).
  | PCMPEQQ = 340
  /// Compare packed words for equal.
  | PCMPEQW = 341
  /// Packed Compare Explicit Length Strings, Return Index.
  | PCMPESTRI = 342
  /// Packed Compare Explicit Length Strings, Return Mask.
  | PCMPESTRM = 343
  /// Compare Packed Signed Integers for Greater Than (byte).
  | PCMPGTB = 344
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | PCMPGTD = 345
  /// Performs logical compare of greater-than on packed integer quadwords.
  | PCMPGTQ = 346
  /// Compare Packed Signed Integers for Greater Than (word).
  | PCMPGTW = 347
  /// Packed Compare Implicit Length Strings, Return Index.
  | PCMPISTRI = 348
  /// Packed Compare Implicit Length Strings, Return Mask.
  | PCMPISTRM = 349
  /// Extract Word.
  | PEXTRW = 350
  /// Packed Horizontal Add.
  | PHADDD = 351
  /// Packed Horizontal Add and Saturate.
  | PHADDSW = 352
  /// Packed Horizontal Add.
  | PHADDW = 353
  /// Packed Horizontal Word Minimum.
  | PHMINPOSUW = 354
  /// Packed Horizontal Subtract.
  | PHSUBD = 355
  /// Packed Horizontal Subtract and Saturate.
  | PHSUBSW = 356
  /// Packed Horizontal Subtract.
  | PHSUBW = 357
  /// Insert Byte.
  | PINSRB = 358
  /// Insert Word.
  | PINSRW = 359
  /// Multiply and Add Packed Integers.
  | PMADDWD = 360
  /// Compare packed signed byte integers.
  | PMAXSB = 361
  /// Compare packed signed dword integers.
  | PMAXSD = 362
  /// Maximum of Packed Signed Word Integers.
  | PMAXSW = 363
  /// Maximum of Packed Unsigned Byte Integers.
  | PMAXUB = 364
  /// Compare packed unsigned dword integers.
  | PMAXUD = 365
  /// Compare packed unsigned word integers.
  | PMAXUW = 366
  /// Minimum of Packed Signed Byte Integers.
  | PMINSB = 367
  /// Compare packed signed dword integers.
  | PMINSD = 368
  /// Minimum of Packed Signed Word Integers.
  | PMINSW = 369
  /// Minimum of Packed Unsigned Byte Integers.
  | PMINUB = 370
  /// Minimum of Packed Dword Integers.
  | PMINUD = 371
  /// Compare packed unsigned word integers.
  | PMINUW = 372
  /// Move Byte Mask.
  | PMOVMSKB = 373
  /// Packed Move with Sign Extend.
  | PMOVSXBD = 374
  /// Packed Move with Sign Extend.
  | PMOVSXBQ = 375
  /// Packed Move with Sign Extend.
  | PMOVSXBW = 376
  /// Packed Move with Sign Extend.
  | PMOVSXDQ = 377
  /// Packed Move with Sign Extend.
  | PMOVSXWD = 378
  /// Packed Move with Sign Extend.
  | PMOVSXWQ = 379
  /// Packed Move with Zero Extend.
  | PMOVZXBD = 380
  /// Packed Move with Zero Extend.
  | PMOVZXBQ = 381
  /// Packed Move with Zero Extend.
  | PMOVZXBW = 382
  /// Packed Move with Zero Extend.
  | PMOVZXDQ = 383
  /// Packed Move with Zero Extend.
  | PMOVZXWD = 384
  /// Packed Move with Zero Extend.
  | PMOVZXWQ = 385
  /// Multiply Packed Doubleword Integers.
  | PMULDQ = 386
  /// Packed Multiply High with Round and Scale.
  | PMULHRSW = 387
  /// Multiply Packed Unsigned Integers and Store High Result.
  | PMULHUW = 388
  /// Multiply Packed Signed Integers and Store High Result.
  | PMULHW = 389
  /// Multiply Packed Integers and Store Low Result.
  | PMULLD = 390
  /// Multiply Packed Signed Integers and Store Low Result.
  | PMULLW = 391
  /// Multiply Packed Unsigned Doubleword Integers.
  | PMULUDQ = 392
  /// Pop a Value from the Stack.
  | POP = 393
  /// Pop All General-Purpose Registers (word).
  | POPA = 394
  /// Pop All General-Purpose Registers (doubleword).
  | POPAD = 395
  /// Return the Count of Number of Bits Set to 1.
  | POPCNT = 396
  /// Pop Stack into EFLAGS Register (lower 16bits EFLAGS).
  | POPF = 397
  /// Pop Stack into EFLAGS Register (EFLAGS).
  | POPFD = 398
  /// Pop Stack into EFLAGS Register (RFLAGS).
  | POPFQ = 399
  /// Bitwise Logical OR.
  | POR = 400
  /// Prefetch Data Into Caches (using NTA hint).
  | PREFETCHNTA = 401
  /// Prefetch Data Into Caches (using T0 hint).
  | PREFETCHT0 = 402
  /// Prefetch Data Into Caches (using T1 hint).
  | PREFETCHT1 = 403
  /// Prefetch Data Into Caches (using T2 hint).
  | PREFETCHT2 = 404
  /// Prefetch Data into Caches in Anticipation of a Write.
  | PREFETCHW = 405
  /// Prefetch Vector Data Into Caches with Intent to Write and T1 Hint.
  | PREFETCHWT1 = 406
  /// Compute Sum of Absolute Differences.
  | PSADBW = 407
  /// Packed Shuffle Bytes.
  | PSHUFB = 408
  /// Shuffle Packed Doublewords.
  | PSHUFD = 409
  /// Shuffle Packed High Words.
  | PSHUFHW = 410
  /// Shuffle Packed Low Words.
  | PSHUFLW = 411
  /// Shuffle Packed Words.
  | PSHUFW = 412
  /// Packed Sign Byte.
  | PSIGNB = 413
  /// Packed Sign Doubleword.
  | PSIGND = 414
  /// Packed Sign Word.
  | PSIGNW = 415
  /// Shift Packed Data Left Logical (doubleword).
  | PSLLD = 416
  /// Shift Double Quadword Left Logical.
  | PSLLDQ = 417
  /// Shift Packed Data Left Logical (quadword).
  | PSLLQ = 418
  /// Shift Packed Data Left Logical (word).
  | PSLLW = 419
  /// Shift Packed Data Right Arithmetic (doubleword).
  | PSRAD = 420
  /// Shift Packed Data Right Arithmetic (word).
  | PSRAW = 421
  /// Shift Packed Data Right Logical (doubleword).
  | PSRLD = 422
  /// Shift Double Quadword Right Logical.
  | PSRLDQ = 423
  /// Shift Packed Data Right Logical (quadword).
  | PSRLQ = 424
  /// Shift Packed Data Right Logical (word).
  | PSRLW = 425
  /// Subtract Packed Integers (byte).
  | PSUBB = 426
  /// Subtract Packed Integers (doubleword).
  | PSUBD = 427
  /// Subtract Packed Integers (quadword).
  | PSUBQ = 428
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | PSUBSB = 429
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | PSUBSW = 430
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | PSUBUSB = 431
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | PSUBUSW = 432
  /// Subtract Packed Integers (word).
  | PSUBW = 433
  /// Logical Compare.
  | PTEST = 434
  /// Unpack High Data.
  | PUNPCKHBW = 435
  /// Unpack High Data.
  | PUNPCKHDQ = 436
  /// Unpack High Data.
  | PUNPCKHQDQ = 437
  /// Unpack High Data.
  | PUNPCKHWD = 438
  /// Unpack Low Data.
  | PUNPCKLBW = 439
  /// Unpack Low Data.
  | PUNPCKLDQ = 440
  /// Unpack Low Data.
  | PUNPCKLQDQ = 441
  /// Unpack Low Data.
  | PUNPCKLWD = 442
  /// Push Word, Doubleword or Quadword Onto the Stack.
  | PUSH = 443
  /// Push All General-Purpose Registers (word).
  | PUSHA = 444
  /// Push All General-Purpose Registers (doubleword).
  | PUSHAD = 445
  /// Push EFLAGS Register onto the Stack (16bits of EFLAGS).
  | PUSHF = 446
  /// Push EFLAGS Register onto the Stack (EFLAGS).
  | PUSHFD = 447
  /// Push EFLAGS Register onto the Stack (RFLAGS).
  | PUSHFQ = 448
  /// Logical Exclusive OR.
  | PXOR = 449
  /// Rotate x bits (CF, r/m(x)) left once.
  | RCL = 450
  /// Rotate x bits (CF, r/m(x)) right once.
  | RCR = 451
  /// Read FS Segment Base.
  | RDFSBASE = 452
  /// Read GS Segment Base.
  | RDGSBASE = 453
  /// Read from Model Specific Register.
  | RDMSR = 454
  /// Read Protection Key Rights for User Pages.
  | RDPKRU = 455
  /// Read Performance-Monitoring Counters.
  | RDPMC = 456
  /// Read Random Number.
  | RDRAND = 457
  /// Read Random SEED.
  | RDSEED = 458
  /// Read Time-Stamp Counter.
  | RDTSC = 459
  /// Read Time-Stamp Counter and Processor ID.
  | RDTSCP = 460
  /// Far return.
  | RETFar = 461
  /// Far return w/ immediate.
  | RETFarImm = 462
  /// Near return.
  | RETNear = 463
  /// Near return w/ immediate .
  | RETNearImm = 464
  /// Rotate x bits r/m(x) left once..
  | ROL = 465
  /// Rotate x bits r/m(x) right once.
  | ROR = 466
  /// Round Scalar Double Precision Floating-Point Values.
  | ROUNDSD = 467
  /// Resume from System Management Mode.
  | RSM = 468
  /// Store AH into Flags.
  | SAHF = 469
  /// Shift.
  | SAR = 470
  /// Integer Subtraction with Borrow.
  | SBB = 471
  /// Scan String (byte).
  | SCASB = 472
  /// Scan String (doubleword).
  | SCASD = 473
  /// Scan String (quadword).
  | SCASQ = 474
  /// Scan String (word).
  | SCASW = 475
  /// Set byte if above (CF=0 and ZF=0).
  | SETA = 476
  /// Set byte if below (CF=1).
  | SETB = 477
  /// Set byte if below or equal (CF=1 or ZF=1).
  | SETBE = 478
  /// Set byte if greater (ZF=0 and SF=OF)..
  | SETG = 479
  /// Set byte if less (SF≠ OF).
  | SETL = 480
  /// Set byte if less or equal (ZF=1 or SF≠ OF).
  | SETLE = 481
  /// Set byte if not below (CF=0).
  | SETNB = 482
  /// Set byte if not less (SF=OF).
  | SETNL = 483
  /// Set byte if not overflow (OF=0).
  | SETNO = 484
  /// Set byte if not parity (PF=0).
  | SETNP = 485
  /// Set byte if not sign (SF=0).
  | SETNS = 486
  /// Set byte if not zero (ZF=0).
  | SETNZ = 487
  /// Set byte if overflow (OF=1).
  | SETO = 488
  /// Set byte if parity (PF=1).
  | SETP = 489
  /// Set byte if sign (SF=1).
  | SETS = 490
  /// Set byte if sign (ZF=1).
  | SETZ = 491
  /// Store Fence.
  | SFENCE = 492
  /// Store Global Descriptor Table Register.
  | SGDT = 493
  /// Shift.
  | SHL = 494
  /// Double Precision Shift Left.
  | SHLD = 495
  /// Shift.
  | SHR = 496
  /// Double Precision Shift Right.
  | SHRD = 497
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | SHUFPD = 498
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | SHUFPS = 499
  /// Store Interrupt Descriptor Table Register.
  | SIDT = 500
  /// Store Local Descriptor Table Register.
  | SLDT = 501
  /// Store Machine Status Word.
  | SMSW = 502
  /// Set AC Flag in EFLAGS Register.
  | STAC = 503
  /// Set Carry Flag.
  | STC = 504
  /// Set Direction Flag.
  | STD = 505
  /// Set Interrupt Flag.
  | STI = 506
  /// Store MXCSR Register State.
  | STMXCSR = 507
  /// Store String (store AL).
  | STOSB = 508
  /// Store String (store EAX).
  | STOSD = 509
  /// Store String (store RAX).
  | STOSQ = 510
  /// Store String (store AX).
  | STOSW = 511
  /// Store Task Register.
  | STR = 512
  /// Subtract.
  | SUB = 513
  /// Subtract Packed Double-Precision Floating-Point Values.
  | SUBPD = 514
  /// Subtract Packed Single-Precision Floating-Point Values.
  | SUBPS = 515
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | SUBSD = 516
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | SUBSS = 517
  /// Swap GS Base Register.
  | SWAPGS = 518
  /// Fast System Call.
  | SYSCALL = 519
  /// Fast System Call.
  | SYSENTER = 520
  /// Fast Return from Fast System Call.
  | SYSEXIT = 521
  /// Return From Fast System Call.
  | SYSRET = 522
  /// Logical Compare.
  | TEST = 523
  /// Count the Number of Trailing Zero Bits.
  | TZCNT = 524
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | UCOMISD = 525
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | UCOMISS = 526
  /// Undefined Instruction (Raise invalid opcode exception).
  | UD2 = 527
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | UNPCKHPD = 528
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | UNPCKHPS = 529
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | UNPCKLPD = 530
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | UNPCKLPS = 531
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPD = 532
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPS = 533
  /// Add Scalar Double-Precision Floating-Point Values.
  | VADDSD = 534
  /// Add Scalar Single-Precision Floating-Point Values.
  | VADDSS = 535
  /// Bitwise Logical AND of Packed Double-Precision Floating-Point Values.
  | VANDNPD = 536
  /// Bitwise Logical AND of Packed Single-Precision Floating-Point Values.
  | VANDNPS = 537
  /// Bitwise Logical AND NOT of Packed Double-Precision Floating-Point Values.
  | VANDPD = 538
  /// Bitwise Logical AND NOT of Packed Single-Precision Floating-Point Values.
  | VANDPS = 539
  /// Broadcast 128 bits of int data in mem to low and high 128-bits in ymm1.
  | VBROADCASTI128 = 540
  /// Broadcast Floating-Point Data.
  | VBROADCASTSS = 541
  /// Compare Scalar Ordered Double-Precision FP Values and Set EFLAGS.
  | VCOMISD = 542
  /// Compare Scalar Ordered Single-Precision FP Values and Set EFLAGS.
  | VCOMISS = 543
  /// Convert Scalar Double-Precision FP Value to Integer.
  | VCVTSD2SI = 544
  /// Convert Dword Integer to Scalar Double-Precision FP Value.
  | VCVTSI2SD = 545
  /// Convert Dword Integer to Scalar Single-Precision FP Value.
  | VCVTSI2SS = 546
  /// Convert Scalar Single-Precision FP Value to Dword Integer.
  | VCVTSS2SI = 547
  /// Convert with Truncation Scalar Double-Precision FP Value to Signed.
  | VCVTTSD2SI = 548
  /// Convert with Truncation Scalar Single-Precision FP Value to Dword Integer.
  | VCVTTSS2SI = 549
  /// Divide Packed Double-Precision Floating-Point Values.
  | VDIVPD = 550
  /// Divide Packed Single-Precision Floating-Point Values.
  | VDIVPS = 551
  /// Divide Scalar Double-Precision Floating-Point Values.
  | VDIVSD = 552
  /// Divide Scalar Single-Precision Floating-Point Values.
  | VDIVSS = 553
  /// Verify a Segment for Reading.
  | VERR = 554
  /// Verify a Segment for Writing.
  | VERW = 555
  /// Insert Packed Integer Values.
  | VINSERTI128 = 556
  /// Load Unaligned Integer 128 Bits.
  | VLDDQU = 557
  /// Call to VM Monitor.
  | VMCALL = 558
  /// Clear Virtual-Machine Control Structure.
  | VMCLEAR = 559
  /// Invoke VM function.
  | VMFUNC = 560
  /// Launch Virtual Machine.
  | VMLAUNCH = 561
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | VMOVAPD = 562
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | VMOVAPS = 563
  /// Move Doubleword.
  | VMOVD = 564
  /// Move One Double-FP and Duplicate.
  | VMOVDDUP = 565
  /// Move Aligned Double Quadword.
  | VMOVDQA = 566
  /// Move Aligned Double Quadword.
  | VMOVDQA32 = 567
  /// Move Aligned Double Quadword.
  | VMOVDQA64 = 568
  /// Move Unaligned Double Quadword.
  | VMOVDQU = 569
  /// Move Unaligned Double Quadword.
  | VMOVDQU32 = 570
  /// Move Unaligned Double Quadword.
  | VMOVDQU64 = 571
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | VMOVHLPS = 572
  /// Move High Packed Double-Precision Floating-Point Value.
  | VMOVHPD = 573
  /// Move High Packed Single-Precision Floating-Point Values.
  | VMOVHPS = 574
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | VMOVLHPS = 575
  /// Move Low Packed Double-Precision Floating-Point Value.
  | VMOVLPD = 576
  /// Move Low Packed Single-Precision Floating-Point Values.
  | VMOVLPS = 577
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | VMOVMSKPD = 578
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | VMOVMSKPS = 579
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | VMOVNTDQ = 580
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPD = 581
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPS = 582
  /// Move Quadword.
  | VMOVQ = 583
  /// Move Data from String to String (doubleword)..
  | VMOVSD = 584
  /// Move Packed Single-FP High and Duplicate.
  | VMOVSHDUP = 585
  /// Move Packed Single-FP Low and Duplicate.
  | VMOVSLDUP = 586
  /// Move Scalar Single-Precision Floating-Point Values.
  | VMOVSS = 587
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | VMOVUPD = 588
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | VMOVUPS = 589
  /// Load Pointer to Virtual-Machine Control Structure.
  | VMPTRLD = 590
  /// Store Pointer to Virtual-Machine Control Structure.
  | VMPTRST = 591
  /// Resume Virtual Machine.
  | VMRESUME = 592
  /// Multiply Packed Double-Precision Floating-Point Values.
  | VMULPD = 593
  /// Multiply Packed Single-Precision Floating-Point Values.
  | VMULPS = 594
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | VMULSD = 595
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | VMULSS = 596
  /// Leave VMX Operation.
  | VMXOFF = 597
  /// Enter VMX Operation.
  | VMXON = 598
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | VORPD = 599
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | VORPS = 600
  /// Packed Absolute Value (byte).
  | VPABSB = 601
  /// Packed Absolute Value (dword).
  | VPABSD = 602
  /// Packed Absolute Value (word).
  | VPABSW = 603
  /// Pack with Signed Saturation.
  | VPACKSSDW = 604
  /// Pack with Signed Saturation.
  | VPACKSSWB = 605
  /// Pack with Unsigned Saturation.
  | VPACKUSDW = 606
  /// Pack with Unsigned Saturation.
  | VPACKUSWB = 607
  /// Add Packed byte Integers.
  | VPADDB = 608
  /// Add Packed Doubleword Integers.
  | VPADDD = 609
  /// Add Packed Quadword Integers.
  | VPADDQ = 610
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | VPADDSB = 611
  /// Add Packed Signed Integers with Signed Saturation (word).
  | VPADDSW = 612
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPADDUSB = 613
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | VPADDUSW = 614
  /// Add Packed word Integers.
  | VPADDW = 615
  /// Packed Align Right.
  | VPALIGNR = 616
  /// Logical AND.
  | VPAND = 617
  /// Logical AND NOT.
  | VPANDN = 618
  /// Average Packed Integers (byte).
  | VPAVGB = 619
  /// Average Packed Integers (word).
  | VPAVGW = 620
  /// Broadcast Integer Data.
  | VPBROADCASTB = 621
  /// Compare Packed Data for Equal (byte).
  | VPCMPEQB = 622
  /// Compare Packed Data for Equal (doubleword).
  | VPCMPEQD = 623
  /// Compare Packed Data for Equal (quadword).
  | VPCMPEQQ = 624
  /// Compare Packed Data for Equal (word).
  | VPCMPEQW = 625
  /// Packed Compare Explicit Length Strings, Return Index.
  | VPCMPESTRI = 626
  /// Packed Compare Explicit Length Strings, Return Mask.
  | VPCMPESTRM = 627
  /// Compare Packed Signed Integers for Greater Than (byte).
  | VPCMPGTB = 628
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | VPCMPGTD = 629
  /// Compare Packed Data for Greater Than (qword).
  | VPCMPGTQ = 630
  /// Compare Packed Signed Integers for Greater Than (word).
  | VPCMPGTW = 631
  /// Packed Compare Implicit Length Strings, Return Index.
  | VPCMPISTRI = 632
  /// Packed Compare Implicit Length Strings, Return Mask.
  | VPCMPISTRM = 633
  /// Extract Word.
  | VPEXTRW = 634
  /// Packed Horizontal Add (32-bit).
  | VPHADDD = 635
  /// Packed Horizontal Add and Saturate (16-bit).
  | VPHADDSW = 636
  /// Packed Horizontal Add (16-bit).
  | VPHADDW = 637
  /// Packed Horizontal Word Minimum.
  | VPHMINPOSUW = 638
  /// Packed Horizontal Subtract (32-bit).
  | VPHSUBD = 639
  /// Packed Horizontal Subtract and Saturate (16-bit)
  | VPHSUBSW = 640
  /// Packed Horizontal Subtract (16-bit).
  | VPHSUBW = 641
  /// Insert Byte.
  | VPINSRB = 642
  /// Insert Word.
  | VPINSRW = 643
  /// Multiply and Add Packed Integers.
  | VPMADDWD = 644
  /// Maximum of Packed Signed Integers (byte).
  | VPMAXSB = 645
  /// Maximum of Packed Signed Integers (dword).
  | VPMAXSD = 646
  /// Maximum of Packed Signed Word Integers.
  | VPMAXSW = 647
  /// Maximum of Packed Unsigned Byte Integers.
  | VPMAXUB = 648
  /// Maximum of Packed Unsigned Integers (dword).
  | VPMAXUD = 649
  /// Maximum of Packed Unsigned Integers (word).
  | VPMAXUW = 650
  /// Minimum of Packed Signed Integers (byte).
  | VPMINSB = 651
  /// Minimum of Packed Signed Integers (dword).
  | VPMINSD = 652
  /// Minimum of Packed Signed Word Integers.
  | VPMINSW = 653
  /// Minimum of Packed Unsigned Byte Integers.
  | VPMINUB = 654
  /// Minimum of Packed Dword Integers.
  | VPMINUD = 655
  /// Minimum of Packed Unsigned Integers (word).
  | VPMINUW = 656
  /// Move Byte Mask.
  | VPMOVMSKB = 657
  /// Packed Move with Sign Extend (8-bit to 32-bit).
  | VPMOVSXBD = 658
  /// Packed Move with Sign Extend (8-bit to 64-bit).
  | VPMOVSXBQ = 659
  /// Packed Move with Sign Extend (8-bit to 16-bit).
  | VPMOVSXBW = 660
  /// Packed Move with Sign Extend (32-bit to 64-bit).
  | VPMOVSXDQ = 661
  /// Packed Move with Sign Extend (16-bit to 32-bit).
  | VPMOVSXWD = 662
  /// Packed Move with Sign Extend (16-bit to 64-bit).
  | VPMOVSXWQ = 663
  /// Packed Move with Zero Extend (8-bit to 32-bit).
  | VPMOVZXBD = 664
  /// Packed Move with Zero Extend (8-bit to 64-bit).
  | VPMOVZXBQ = 665
  /// Packed Move with Zero Extend (8-bit to 16-bit).
  | VPMOVZXBW = 666
  /// Packed Move with Zero Extend (32-bit to 64-bit).
  | VPMOVZXDQ = 667
  /// Packed Move with Zero Extend (16-bit to 32-bit).
  | VPMOVZXWD = 668
  /// Packed Move with Zero Extend (16-bit to 64-bit).
  | VPMOVZXWQ = 669
  /// Multiply Packed Doubleword Integers.
  | VPMULDQ = 670
  /// Packed Multiply High with Round and Scale.
  | VPMULHRSW = 671
  /// Multiply Packed Unsigned Integers and Store High Result.
  | VPMULHUW = 672
  /// Multiply Packed Signed Integers and Store High Result.
  | VPMULHW = 673
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLD = 674
  /// Multiply Packed Signed Integers and Store Low Result.
  | VPMULLW = 675
  /// Multiply Packed Unsigned Doubleword Integers.
  | VPMULUDQ = 676
  /// Bitwise Logical OR.
  | VPOR = 677
  /// Compute Sum of Absolute Differences.
  | VPSADBW = 678
  /// Packed Shuffle Bytes.
  | VPSHUFB = 679
  /// Shuffle Packed Doublewords.
  | VPSHUFD = 680
  /// Shuffle Packed High Words.
  | VPSHUFHW = 681
  /// Shuffle Packed Low Words.
  | VPSHUFLW = 682
  /// Packed SIGN (byte).
  | VPSIGNB = 683
  /// Packed SIGN (doubleword).
  | VPSIGND = 684
  /// Packed SIGN (word).
  | VPSIGNW = 685
  /// Shift Packed Data Left Logical (doubleword).
  | VPSLLD = 686
  /// Shift Double Quadword Left Logical.
  | VPSLLDQ = 687
  /// Shift Packed Data Left Logical (quadword).
  | VPSLLQ = 688
  /// Shift Packed Data Left Logical (word).
  | VPSLLW = 689
  /// Shift Packed Data Right Arithmetic (doubleword).
  | VPSRAD = 690
  /// Shift Packed Data Right Arithmetic (word).
  | VPSRAW = 691
  /// Shift Packed Data Right Logical (doubleword).
  | VPSRLD = 692
  /// Shift Double Quadword Right Logical.
  | VPSRLDQ = 693
  /// Shift Packed Data Right Logical (quadword).
  | VPSRLQ = 694
  /// Shift Packed Data Right Logical (word).
  | VPSRLW = 695
  /// Subtract Packed Integers (byte).
  | VPSUBB = 696
  /// Subtract Packed Integers (doubleword).
  | VPSUBD = 697
  /// Subtract Packed Integers (quadword).
  | VPSUBQ = 698
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | VPSUBSB = 699
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | VPSUBSW = 700
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPSUBUSB = 701
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | VPSUBUSW = 702
  /// Subtract Packed Integers (word).
  | VPSUBW = 703
  /// Logical Compare.
  | VPTEST = 704
  /// Unpack High Data.
  | VPUNPCKHBW = 705
  /// Unpack High Data.
  | VPUNPCKHDQ = 706
  /// Unpack High Data.
  | VPUNPCKHQDQ = 707
  /// Unpack High Data.
  | VPUNPCKHWD = 708
  /// Unpack Low Data.
  | VPUNPCKLBW = 709
  /// Unpack Low Data.
  | VPUNPCKLDQ = 710
  /// Unpack Low Data.
  | VPUNPCKLQDQ = 711
  /// Unpack Low Data.
  | VPUNPCKLWD = 712
  /// Logical Exclusive OR.
  | VPXOR = 713
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | VSHUFPD = 714
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | VSHUFPS = 715
  /// Subtract Packed Double-Precision Floating-Point Values.
  | VSUBPD = 716
  /// Subtract Packed Single-Precision Floating-Point Values.
  | VSUBPS = 717
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | VSUBSD = 718
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | VSUBSS = 719
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | VUCOMISD = 720
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | VUCOMISS = 721
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | VUNPCKHPD = 722
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | VUNPCKHPS = 723
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | VUNPCKLPD = 724
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | VUNPCKLPS = 725
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | VXORPD = 726
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | VXORPS = 727
  /// Zero Upper Bits of YMM Registers.
  | VZEROUPPER = 728
  /// Wait.
  | WAIT = 729
  /// Write Back and Invalidate Cache.
  | WBINVD = 730
  /// Write FS Segment Base.
  | WRFSBASE = 731
  /// Write GS Segment Base.
  | WRGSBASE = 732
  /// Write to Model Specific Register.
  | WRMSR = 733
  /// Write Data to User Page Key Register.
  | WRPKRU = 734
  /// Transactional Abort.
  | XABORT = 735
  /// Exchange and Add.
  | XADD = 736
  /// Transactional Begin.
  | XBEGIN = 737
  /// Exchange Register/Memory with Register.
  | XCHG = 738
  /// Transactional End.
  | XEND = 739
  /// Value of Extended Control Register.
  | XGETBV = 740
  /// Table Look-up Translation.
  | XLATB = 741
  /// Logical Exclusive OR.
  | XOR = 742
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | XORPD = 743
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | XORPS = 744
  /// Restore Processor Extended States.
  | XRSTOR = 745
  /// Save Processor Extended States.
  | XSAVE = 746
  /// Save processor extended states with compaction to memory.
  | XSAVEC = 747
  /// Save processor extended states with compaction to memory.
  | XSAVEC64 = 748
  /// Save Processor Extended States Optimized.
  | XSAVEOPT = 749
  /// Set Extended Control Register.
  | XSETBV = 750
  /// Test If In Transactional Execution.
  | XTEST = 751
  /// Invalid Opcode.
  | InvalOP = 752

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
  /// Bound Register
  | BndR = 0x2
  /// Bound Register or memory
  | BndM = 0x3
  /// The reg field of the ModR/M byte selects a control register
  | C = 0x4
  /// The reg field of the ModR/M byte selects a debug register
  | D = 0x5
  /// General Register or Memory
  | E = 0x6
  /// General Register
  | G = 0x7
  /// The VEX.vvvv field of the VEX prefix selects a 128-bit XMM register or a
  /// 256-bit YMM regerister, determined by operand type
  | H = 0x8
  /// Unsigned Immediate
  | I = 0x9
  /// Signed Immediate
  | SI = 0xa
  /// EIP relative offset
  | J = 0xb
  /// Memory
  | M = 0xc
  /// A ModR/M follows the opcode and specifies the operand. The operand is
  /// either a 128-bit, 256-bit or 512-bit memory location.
  | MZ = 0xd
  /// The R/M field of the ModR/M byte selects a packed-quadword, MMX
  /// technology register
  | N = 0xe
  /// No ModR/M byte. No base register, index register, or scaling factor
  | O = 0xf
  /// The reg field of the ModR/M byte selects a packed quadword MMX technology
  /// register
  | P = 0x10
  /// A ModR/M byte follows the opcode and specifies the operand. The operand
  /// is either an MMX technology register of a memory address
  | Q = 0x11
  /// The R/M field of the ModR/M byte may refer only to a general register
  | R = 0x12
  /// The reg field of the ModR/M byte selects a segment register
  | S = 0x13
  /// The R/M field of the ModR/M byte selects a 128-bit XMM register or a
  /// 256-bit YMM register, determined by operand type
  | U = 0x14
  /// The reg field of the ModR/M byte selects a 128-bit XMM register or a
  /// 256-bit YMM register, determined by operand type
  | V = 0x15
  /// The reg field of the ModR/M byte selects a 128-bit XMM register or a
  /// 256-bit YMM register, 512-bit ZMM register determined by operand type
  | VZ = 0x16
  /// A ModR/M follows the opcode and specifies the operand. The operand is
  /// either a 128-bit XMM register, a 256-bit YMM register, or a memory address
  | W = 0x17
  /// A ModR/M follows the opcode and specifies the operand. The operand is
  /// either a 128-bit XMM register, a 256-bit YMM register, a 512-bit ZMM
  /// register or a memory address
  | WZ = 0x18
  /// Memory addressed by the DS:rSI register pair.
  | X = 0x19
  /// Memory addressed by the ES:rDI register pair.
  | Y = 0x1a
  /// The reg field of the ModR/M byte is 0b000
  | E0 = 0x1b

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
  /// Register size = Double-quadword, Pointer size = Quadword
  | DQQ = 0x200
  /// Register size = Double-quadword, Pointer size = Word
  | DQW = 0x240
  /// Register size = Doubledword, Pointer size = Word
  | DW = 0x280
  /// 32-bit, 48 bit, or 80-bit pointer, depending on operand-size attribute
  | P = 0x2c0
  /// 128-bit or 256-bit packed double-precision floating-point data
  | PD = 0x300
  /// Quadword MMX techonolgy register
  | PI = 0x340
  /// 128-bit or 256-bit packed single-precision floating-point data
  | PS = 0x380
  /// 128-bit or 256-bit packed single-precision floating-point data, pointer
  /// size : Quadword
  | PSQ = 0x3c0
  /// Quadword, regardless of operand-size attribute
  | Q = 0x400
  /// Quad-Quadword (256-bits), regardless of operand-size attribute
  | QQ = 0x440
  /// 6-byte or 10-byte pseudo-descriptor
  | S = 0x480
  /// Scalar element of a 128-bit double-precision floating data
  | SD = 0x4c0
  /// Scalar element of a 128-bit double-precision floating data, but the
  /// pointer size is quadword
  | SDQ = 0x500
  /// Scalar element of a 128-bit single-precision floating data
  | SS = 0x540
  /// Scalar element of a 128-bit single-precision floating data, but the
  /// pointer size is doubleword
  | SSD = 0x580
  /// Scalar element of a 128-bit single-precision floating data, but the
  /// pointer size is quadword
  | SSQ = 0x5c0
  /// Word/DWord/QWord depending on operand-size attribute
  | V = 0x600
  /// Word, regardless of operand-size attribute
  | W = 0x640
  /// dq or qq based on the operand-size attribute
  | X = 0x680
  /// 128-bit, 256-bit or 512-bit depending on operand-size attribute
  | XZ = 0x6c0
  /// Doubleword or quadword (in 64-bit mode), depending on operand-size
  /// attribute
  | Y = 0x700
  /// Word for 16-bit operand-size or DWord for 32 or 64-bit operand size
  | Z = 0x740

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
