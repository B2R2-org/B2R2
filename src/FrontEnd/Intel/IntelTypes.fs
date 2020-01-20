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
  /// Conditional Move (Move if above (CF = 0 and ZF = 0)).
  | CMOVA = 37
  /// Conditional Move (Move if above or equal (CF = 0)).
  | CMOVAE = 38
  /// Conditional Move (Move if below (CF = 1)).
  | CMOVB = 39
  /// Conditional Move (Move if below or equal (CF = 1 or ZF = 1)).
  | CMOVBE = 40
  /// Conditional Move (Move if greater (ZF = 0 and SF = OF)).
  | CMOVG = 41
  /// Conditional Move (Move if greater or equal (SF = OF)).
  | CMOVGE = 42
  /// Conditional Move (Move if less (SF <> OF)).
  | CMOVL = 43
  /// Conditional Move (Move if less or equal (ZF = 1 or SF <> OF)).
  | CMOVLE = 44
  /// Conditional Move (Move if not overflow (OF = 0)).
  | CMOVNO = 45
  /// Conditional Move (Move if not parity (PF = 0)).
  | CMOVNP = 46
  /// Conditional Move (Move if not sign (SF = 0)).
  | CMOVNS = 47
  /// Conditional Move (Move if not zero (ZF = 0)).
  | CMOVNZ = 48
  /// Conditional Move (Move if overflow (OF = 1)).
  | CMOVO = 49
  /// Conditional Move (Move if parity (PF = 1)).
  | CMOVP = 50
  /// Conditional Move (Move if sign (SF = 1)).
  | CMOVS = 51
  /// Conditional Move (Move if zero (ZF = 1)).
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
  /// Empty MMX Technology State.
  | EMMS = 101
  /// Make Stack Frame for Procedure Parameters.
  | ENTER = 102
  /// Compute 2x-1.
  | F2XM1 = 103
  /// Absolute Value.
  | FABS = 104
  /// Add.
  | FADD = 105
  /// Add and pop the register stack.
  | FADDP = 106
  /// Load Binary Coded Decimal.
  | FBLD = 107
  /// Store BCD Integer and Pop.
  | FBSTP = 108
  /// Change Sign.
  | FCHS = 109
  /// Clear Exceptions.
  | FCLEX = 110
  /// Floating-Point Conditional Move (if below (CF = 1)).
  | FCMOVB = 111
  /// Floating-Point Conditional Move (if below or equal (CF = 1 or ZF = 1)).
  | FCMOVBE = 112
  /// Floating-Point Conditional Move (if equal (ZF = 1)).
  | FCMOVE = 113
  /// Floating-Point Conditional Move (if not below (CF = 0)).
  | FCMOVNB = 114
  /// FP Conditional Move (if not below or equal (CF = 0 and ZF = 0)).
  | FCMOVNBE = 115
  /// Floating-Point Conditional Move (if not equal (ZF = 0)).
  | FCMOVNE = 116
  /// Floating-Point Conditional Move (if not unordered (PF = 0)).
  | FCMOVNU = 117
  /// Floating-Point Conditional Move (if unordered (PF = 1)).
  | FCMOVU = 118
  /// Compare Floating Point Values.
  | FCOM = 119
  /// Compare Floating Point Values and Set EFLAGS.
  | FCOMI = 120
  /// Compare Floating Point Values and Set EFLAGS.
  | FCOMIP = 121
  /// Compare Floating Point Values and pop register stack.
  | FCOMP = 122
  /// Compare Floating Point Values and pop register stack twice.
  | FCOMPP = 123
  /// Cosine.
  | FCOS = 124
  /// Decrement Stack-Top Pointer.
  | FDECSTP = 125
  /// Divide.
  | FDIV = 126
  /// Divide and pop the register stack.
  | FDIVP = 127
  /// Reverse Divide.
  | FDIVR = 128
  /// Reverse Divide and pop the register stack.
  | FDIVRP = 129
  /// Free Floating-Point Register.
  | FFREE = 130
  /// Add.
  | FIADD = 131
  /// Compare Integer.
  | FICOM = 132
  /// Compare Integer and pop the register stack.
  | FICOMP = 133
  /// Divide.
  | FIDIV = 134
  /// Reverse Divide.
  | FIDIVR = 135
  /// Load Integer.
  | FILD = 136
  /// Multiply.
  | FIMUL = 137
  /// Increment Stack-Top Pointer.
  | FINCSTP = 138
  /// Initialize Floating-Point Unit.
  | FINIT = 139
  /// Store Integer.
  | FIST = 140
  /// Store Integer and pop the register stack.
  | FISTP = 141
  /// Store Integer with Truncation.
  | FISTTP = 142
  /// Subtract.
  | FISUB = 143
  /// Reverse Subtract.
  | FISUBR = 144
  /// Load Floating Point Value.
  | FLD = 145
  /// Load Constant (Push +1.0 onto the FPU register stack).
  | FLD1 = 146
  /// Load x87 FPU Control Word.
  | FLDCW = 147
  /// Load x87 FPU Environment.
  | FLDENV = 148
  /// Load Constant (Push log2e onto the FPU register stack).
  | FLDL2E = 149
  /// Load Constant (Push log210 onto the FPU register stack).
  | FLDL2T = 150
  /// Load Constant (Push log102 onto the FPU register stack).
  | FLDLG2 = 151
  /// Load Constant (Push loge2 onto the FPU register stack).
  | FLDLN2 = 152
  /// Load Constant (Push Pi onto the FPU register stack).
  | FLDPI = 153
  /// Load Constant (Push +0.0 onto the FPU register stack).
  | FLDZ = 154
  /// Multiply.
  | FMUL = 155
  /// Multiply and pop the register stack.
  | FMULP = 156
  /// No Operation.
  | FNOP = 157
  /// Store x87 FPU Control Word.
  | FNSTCW = 158
  /// Partial Arctangent.
  | FPATAN = 159
  /// Partial Remainder.
  | FPREM = 160
  /// Partial Remainder.
  | FPREM1 = 161
  /// Partial Tangent.
  | FPTAN = 162
  /// Round to Integer.
  | FRNDINT = 163
  /// Restore x87 FPU State.
  | FRSTOR = 164
  /// Store x87 FPU State.
  | FSAVE = 165
  /// Scale.
  | FSCALE = 166
  /// Sine.
  | FSIN = 167
  /// Sine and Cosine.
  | FSINCOS = 168
  /// Square Root.
  | FSQRT = 169
  /// Store Floating Point Value.
  | FST = 170
  /// Store x87 FPU Environment.
  | FSTENV = 171
  /// Store Floating Point Value.
  | FSTP = 172
  /// Store x87 FPU Status Word.
  | FSTSW = 173
  /// Subtract.
  | FSUB = 174
  /// Subtract and pop register stack.
  | FSUBP = 175
  /// Reverse Subtract.
  | FSUBR = 176
  /// Reverse Subtract and pop register stack.
  | FSUBRP = 177
  /// TEST.
  | FTST = 178
  /// Unordered Compare Floating Point Values.
  | FUCOM = 179
  /// Compare Floating Point Values and Set EFLAGS.
  | FUCOMI = 180
  /// Compare Floating Point Values and Set EFLAGS and pop register stack.
  | FUCOMIP = 181
  /// Unordered Compare Floating Point Values.
  | FUCOMP = 182
  /// Unordered Compare Floating Point Values.
  | FUCOMPP = 183
  /// Examine ModR/M.
  | FXAM = 184
  /// Exchange Register Contents.
  | FXCH = 185
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR = 186
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR64 = 187
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE = 188
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE64 = 189
  /// Extract Exponent and Significand.
  | FXTRACT = 190
  /// compute y * log2x.
  | FYL2X = 191
  /// compute y * log2(x+1).
  | FYL2XP1 = 192
  /// GETSEC.
  | GETSEC = 193
  /// Halt.
  | HLT = 194
  /// Signed Divide.
  | IDIV = 195
  /// Signed Multiply.
  | IMUL = 196
  /// Input from Port.
  | IN = 197
  /// Increment by 1.
  | INC = 198
  /// Input from Port to String.
  | INS = 199
  /// Input from Port to String (byte).
  | INSB = 200
  /// Input from Port to String (doubleword).
  | INSD = 201
  /// Input from Port to String (word).
  | INSW = 202
  /// Call to Interrupt (Interrupt vector specified by immediate byte).
  | INT = 203
  /// Call to Interrupt (Interrupt 3?trap to debugger).
  | INT3 = 204
  /// Call to Interrupt (InteInterrupt 4?if overflow flag is 1).
  | INTO = 205
  /// Invalidate Internal Caches.
  | INVD = 206
  /// Invalidate TLB Entries.
  | INVLPG = 207
  /// Interrupt return (32-bit operand size).
  | IRETD = 208
  /// Interrupt return (64-bit operand size).
  | IRETQ = 209
  /// Interrupt return (16-bit operand size).
  | IRETW = 210
  /// Jump if Condition Is Met (Jump short if above, CF = 0 and ZF = 0).
  | JA = 211
  /// Jump if Condition Is Met (Jump short if below, CF = 1).
  | JB = 212
  /// Jump if Condition Is Met (Jump short if below or equal, CF = 1 or ZF).
  | JBE = 213
  /// Jump if Condition Is Met (Jump short if CX register is 0).
  | JCXZ = 214
  /// Jump if Condition Is Met (Jump short if ECX register is 0).
  | JECXZ = 215
  /// Jump if Condition Is Met (Jump short if greater, ZF = 0 and SF = OF).
  | JG = 216
  /// Jump if Condition Is Met (Jump short if less, SF <> OF).
  | JL = 217
  /// Jump if Cond Is Met (Jump short if less or equal, ZF = 1 or SF <> OF).
  | JLE = 218
  /// Far jmp.
  | JMPFar = 219
  /// Near jmp.
  | JMPNear = 220
  /// Jump if Condition Is Met (Jump near if not below, CF = 0).
  | JNB = 221
  /// Jump if Condition Is Met (Jump near if not less, SF = OF).
  | JNL = 222
  /// Jump if Condition Is Met (Jump near if not overflow, OF = 0).
  | JNO = 223
  /// Jump if Condition Is Met (Jump near if not parity, PF = 0).
  | JNP = 224
  /// Jump if Condition Is Met (Jump near if not sign, SF = 0).
  | JNS = 225
  /// Jump if Condition Is Met (Jump near if not zero, ZF = 0).
  | JNZ = 226
  /// Jump if Condition Is Met (Jump near if overflow, OF = 1).
  | JO = 227
  /// Jump if Condition Is Met (Jump near if parity, PF = 1).
  | JP = 228
  /// Jump if Condition Is Met (Jump short if RCX register is 0).
  | JRCXZ = 229
  /// Jump if Condition Is Met (Jump short if sign, SF = 1).
  | JS = 230
  /// Jump if Condition Is Met (Jump short if zero, ZF = 1).
  | JZ = 231
  /// Load Status Flags into AH Register.
  | LAHF = 232
  /// Load Access Rights Byte.
  | LAR = 233
  /// Load Unaligned Integer 128 Bits.
  | LDDQU = 234
  /// Load MXCSR Register.
  | LDMXCSR = 235
  /// Load Far Pointer (DS).
  | LDS = 236
  /// Load Effective Address.
  | LEA = 237
  /// High Level Procedure Exit.
  | LEAVE = 238
  /// Load Far Pointer (ES).
  | LES = 239
  /// Load Fence.
  | LFENCE = 240
  /// Load Far Pointer (FS).
  | LFS = 241
  /// Load GlobalDescriptor Table Register.
  | LGDT = 242
  /// Load Far Pointer (GS).
  | LGS = 243
  /// Load Interrupt Descriptor Table Register.
  | LIDT = 244
  /// Load Local Descriptor Table Register.
  | LLDT = 245
  /// Load Machine Status Word.
  | LMSW = 246
  /// Load String (byte).
  | LODSB = 247
  /// Load String (doubleword).
  | LODSD = 248
  /// Load String (quadword).
  | LODSQ = 249
  /// Load String (word).
  | LODSW = 250
  /// Loop According to ECX Counter (count <> 0).
  | LOOP = 251
  /// Loop According to ECX Counter (count <> 0 and ZF = 1).
  | LOOPE = 252
  /// Loop According to ECX Counter (count <> 0 and ZF = 0).
  | LOOPNE = 253
  /// Load Segment Limit.
  | LSL = 254
  /// Load Far Pointer (SS).
  | LSS = 255
  /// Load Task Register.
  | LTR = 256
  /// the Number of Leading Zero Bits.
  | LZCNT = 257
  /// Return Maximum Packed Double-Precision Floating-Point Values.
  | MAXPD = 258
  /// Return Maximum Packed Single-Precision Floating-Point Values.
  | MAXPS = 259
  /// Return Maximum Scalar Double-Precision Floating-Point Values.
  | MAXSD = 260
  /// Return Maximum Scalar Single-Precision Floating-Point Values.
  | MAXSS = 261
  /// Memory Fence.
  | MFENCE = 262
  /// Return Minimum Packed Double-Precision Floating-Point Values.
  | MINPD = 263
  /// Return Minimum Packed Single-Precision Floating-Point Values.
  | MINPS = 264
  /// Return Minimum Scalar Double-Precision Floating-Point Values.
  | MINSD = 265
  /// Return Minimum Scalar Single-Precision Floating-Point Values.
  | MINSS = 266
  /// Set Up Monitor Address.
  | MONITOR = 267
  /// MOV.
  | MOV = 268
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | MOVAPD = 269
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | MOVAPS = 270
  /// Move Data After Swapping Bytes.
  | MOVBE = 271
  /// Move Doubleword.
  | MOVD = 272
  /// Move One Double-FP and Duplicate.
  | MOVDDUP = 273
  /// Move Quadword from XMM to MMX Technology Register.
  | MOVDQ2Q = 274
  /// Move Aligned Double Quadword.
  | MOVDQA = 275
  /// Move Unaligned Double Quadword.
  | MOVDQU = 276
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | MOVHLPS = 277
  /// Move High Packed Double-Precision Floating-Point Value.
  | MOVHPD = 278
  /// Move High Packed Single-Precision Floating-Point Values.
  | MOVHPS = 279
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | MOVLHPS = 280
  /// Move Low Packed Double-Precision Floating-Point Value.
  | MOVLPD = 281
  /// Move Low Packed Single-Precision Floating-Point Values.
  | MOVLPS = 282
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | MOVMSKPD = 283
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | MOVMSKPS = 284
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQ = 285
  /// Store Doubleword Using Non-Temporal Hint.
  | MOVNTI = 286
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPD = 287
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | MOVNTPS = 288
  /// Store of Quadword Using Non-Temporal Hint.
  | MOVNTQ = 289
  /// Move Quadword.
  | MOVQ = 290
  /// Move Quadword from MMX Technology to XMM Register.
  | MOVQ2DQ = 291
  /// Move Data from String to String (byte).
  | MOVSB = 292
  /// Move Data from String to String (doubleword).
  | MOVSD = 293
  /// Move Packed Single-FP High and Duplicate.
  | MOVSHDUP = 294
  /// Move Packed Single-FP Low and Duplicate.
  | MOVSLDUP = 295
  /// Move Data from String to String (quadword).
  | MOVSQ = 296
  /// Move Scalar Single-Precision Floating-Point Values.
  | MOVSS = 297
  /// Move Data from String to String (word).
  | MOVSW = 298
  /// Move with Sign-Extension.
  | MOVSX = 299
  /// Move with Sign-Extension (doubleword to quadword).
  | MOVSXD = 300
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | MOVUPD = 301
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | MOVUPS = 302
  /// Move with Zero-Extend.
  | MOVZX = 303
  /// Unsigned Multiply.
  | MUL = 304
  /// Multiply Packed Double-Precision Floating-Point Values.
  | MULPD = 305
  /// Multiply Packed Single-Precision Floating-Point Values.
  | MULPS = 306
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | MULSD = 307
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | MULSS = 308
  /// Unsigned multiply without affecting arithmetic flags.
  | MULX = 309
  /// Monitor Wait.
  | MWAIT = 310
  /// Two's Complement Negation.
  | NEG = 311
  /// No Operation.
  | NOP = 312
  /// One's Complement Negation.
  | NOT = 313
  /// Logical Inclusive OR.
  | OR = 314
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | ORPD = 315
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | ORPS = 316
  /// Output to Port.
  | OUT = 317
  /// Output String to Port.
  | OUTS = 318
  /// Output String to Port (byte).
  | OUTSB = 319
  /// Output String to Port (doubleword).
  | OUTSD = 320
  /// Output String to Port (word).
  | OUTSW = 321
  /// Computes the absolute value of each signed byte data element.
  | PABSB = 322
  /// Computes the absolute value of each signed 32-bit data element.
  | PABSD = 323
  /// Computes the absolute value of each signed 16-bit data element.
  | PABSW = 324
  /// Pack with Signed Saturation.
  | PACKSSDW = 325
  /// Pack with Signed Saturation.
  | PACKSSWB = 326
  /// Pack with Unsigned Saturation.
  | PACKUSDW = 327
  /// Pack with Unsigned Saturation.
  | PACKUSWB = 328
  /// Add Packed byte Integers.
  | PADDB = 329
  /// Add Packed Doubleword Integers.
  | PADDD = 330
  /// Add Packed Quadword Integers.
  | PADDQ = 331
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | PADDSB = 332
  /// Add Packed Signed Integers with Signed Saturation (word).
  | PADDSW = 333
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | PADDUSB = 334
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | PADDUSW = 335
  /// Add Packed word Integers.
  | PADDW = 336
  /// Packed Align Right.
  | PALIGNR = 337
  /// Logical AND.
  | PAND = 338
  /// Logical AND NOT.
  | PANDN = 339
  /// Spin Loop Hint.
  | PAUSE = 340
  /// Average Packed Integers (byte).
  | PAVGB = 341
  /// Average Packed Integers (word).
  | PAVGW = 342
  /// Compare Packed Data for Equal (byte).
  | PCMPEQB = 343
  /// Compare Packed Data for Equal (doubleword).
  | PCMPEQD = 344
  /// Compare Packed Data for Equal (quadword).
  | PCMPEQQ = 345
  /// Compare packed words for equal.
  | PCMPEQW = 346
  /// Packed Compare Explicit Length Strings, Return Index.
  | PCMPESTRI = 347
  /// Packed Compare Explicit Length Strings, Return Mask.
  | PCMPESTRM = 348
  /// Compare Packed Signed Integers for Greater Than (byte).
  | PCMPGTB = 349
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | PCMPGTD = 350
  /// Performs logical compare of greater-than on packed integer quadwords.
  | PCMPGTQ = 351
  /// Compare Packed Signed Integers for Greater Than (word).
  | PCMPGTW = 352
  /// Packed Compare Implicit Length Strings, Return Index.
  | PCMPISTRI = 353
  /// Packed Compare Implicit Length Strings, Return Mask.
  | PCMPISTRM = 354
  /// Extract Word.
  | PEXTRW = 355
  /// Packed Horizontal Add.
  | PHADDD = 356
  /// Packed Horizontal Add and Saturate.
  | PHADDSW = 357
  /// Packed Horizontal Add.
  | PHADDW = 358
  /// Packed Horizontal Word Minimum.
  | PHMINPOSUW = 359
  /// Packed Horizontal Subtract.
  | PHSUBD = 360
  /// Packed Horizontal Subtract and Saturate.
  | PHSUBSW = 361
  /// Packed Horizontal Subtract.
  | PHSUBW = 362
  /// Insert Byte.
  | PINSRB = 363
  /// Insert Word.
  | PINSRW = 364
  /// Multiply and Add Packed Integers.
  | PMADDWD = 365
  /// Compare packed signed byte integers.
  | PMAXSB = 366
  /// Compare packed signed dword integers.
  | PMAXSD = 367
  /// Maximum of Packed Signed Word Integers.
  | PMAXSW = 368
  /// Maximum of Packed Unsigned Byte Integers.
  | PMAXUB = 369
  /// Compare packed unsigned dword integers.
  | PMAXUD = 370
  /// Compare packed unsigned word integers.
  | PMAXUW = 371
  /// Minimum of Packed Signed Byte Integers.
  | PMINSB = 372
  /// Compare packed signed dword integers.
  | PMINSD = 373
  /// Minimum of Packed Signed Word Integers.
  | PMINSW = 374
  /// Minimum of Packed Unsigned Byte Integers.
  | PMINUB = 375
  /// Minimum of Packed Dword Integers.
  | PMINUD = 376
  /// Compare packed unsigned word integers.
  | PMINUW = 377
  /// Move Byte Mask.
  | PMOVMSKB = 378
  /// Packed Move with Sign Extend.
  | PMOVSXBD = 379
  /// Packed Move with Sign Extend.
  | PMOVSXBQ = 380
  /// Packed Move with Sign Extend.
  | PMOVSXBW = 381
  /// Packed Move with Sign Extend.
  | PMOVSXDQ = 382
  /// Packed Move with Sign Extend.
  | PMOVSXWD = 383
  /// Packed Move with Sign Extend.
  | PMOVSXWQ = 384
  /// Packed Move with Zero Extend.
  | PMOVZXBD = 385
  /// Packed Move with Zero Extend.
  | PMOVZXBQ = 386
  /// Packed Move with Zero Extend.
  | PMOVZXBW = 387
  /// Packed Move with Zero Extend.
  | PMOVZXDQ = 388
  /// Packed Move with Zero Extend.
  | PMOVZXWD = 389
  /// Packed Move with Zero Extend.
  | PMOVZXWQ = 390
  /// Multiply Packed Doubleword Integers.
  | PMULDQ = 391
  /// Packed Multiply High with Round and Scale.
  | PMULHRSW = 392
  /// Multiply Packed Unsigned Integers and Store High Result.
  | PMULHUW = 393
  /// Multiply Packed Signed Integers and Store High Result.
  | PMULHW = 394
  /// Multiply Packed Integers and Store Low Result.
  | PMULLD = 395
  /// Multiply Packed Signed Integers and Store Low Result.
  | PMULLW = 396
  /// Multiply Packed Unsigned Doubleword Integers.
  | PMULUDQ = 397
  /// Pop a Value from the Stack.
  | POP = 398
  /// Pop All General-Purpose Registers (word).
  | POPA = 399
  /// Pop All General-Purpose Registers (doubleword).
  | POPAD = 400
  /// Return the Count of Number of Bits Set to 1.
  | POPCNT = 401
  /// Pop Stack into EFLAGS Register (lower 16bits EFLAGS).
  | POPF = 402
  /// Pop Stack into EFLAGS Register (EFLAGS).
  | POPFD = 403
  /// Pop Stack into EFLAGS Register (RFLAGS).
  | POPFQ = 404
  /// Bitwise Logical OR.
  | POR = 405
  /// Prefetch Data Into Caches (using NTA hint).
  | PREFETCHNTA = 406
  /// Prefetch Data Into Caches (using T0 hint).
  | PREFETCHT0 = 407
  /// Prefetch Data Into Caches (using T1 hint).
  | PREFETCHT1 = 408
  /// Prefetch Data Into Caches (using T2 hint).
  | PREFETCHT2 = 409
  /// Prefetch Data into Caches in Anticipation of a Write.
  | PREFETCHW = 410
  /// Prefetch Vector Data Into Caches with Intent to Write and T1 Hint.
  | PREFETCHWT1 = 411
  /// Compute Sum of Absolute Differences.
  | PSADBW = 412
  /// Packed Shuffle Bytes.
  | PSHUFB = 413
  /// Shuffle Packed Doublewords.
  | PSHUFD = 414
  /// Shuffle Packed High Words.
  | PSHUFHW = 415
  /// Shuffle Packed Low Words.
  | PSHUFLW = 416
  /// Shuffle Packed Words.
  | PSHUFW = 417
  /// Packed Sign Byte.
  | PSIGNB = 418
  /// Packed Sign Doubleword.
  | PSIGND = 419
  /// Packed Sign Word.
  | PSIGNW = 420
  /// Shift Packed Data Left Logical (doubleword).
  | PSLLD = 421
  /// Shift Double Quadword Left Logical.
  | PSLLDQ = 422
  /// Shift Packed Data Left Logical (quadword).
  | PSLLQ = 423
  /// Shift Packed Data Left Logical (word).
  | PSLLW = 424
  /// Shift Packed Data Right Arithmetic (doubleword).
  | PSRAD = 425
  /// Shift Packed Data Right Arithmetic (word).
  | PSRAW = 426
  /// Shift Packed Data Right Logical (doubleword).
  | PSRLD = 427
  /// Shift Double Quadword Right Logical.
  | PSRLDQ = 428
  /// Shift Packed Data Right Logical (quadword).
  | PSRLQ = 429
  /// Shift Packed Data Right Logical (word).
  | PSRLW = 430
  /// Subtract Packed Integers (byte).
  | PSUBB = 431
  /// Subtract Packed Integers (doubleword).
  | PSUBD = 432
  /// Subtract Packed Integers (quadword).
  | PSUBQ = 433
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | PSUBSB = 434
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | PSUBSW = 435
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | PSUBUSB = 436
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | PSUBUSW = 437
  /// Subtract Packed Integers (word).
  | PSUBW = 438
  /// Logical Compare.
  | PTEST = 439
  /// Unpack High Data.
  | PUNPCKHBW = 440
  /// Unpack High Data.
  | PUNPCKHDQ = 441
  /// Unpack High Data.
  | PUNPCKHQDQ = 442
  /// Unpack High Data.
  | PUNPCKHWD = 443
  /// Unpack Low Data.
  | PUNPCKLBW = 444
  /// Unpack Low Data.
  | PUNPCKLDQ = 445
  /// Unpack Low Data.
  | PUNPCKLQDQ = 446
  /// Unpack Low Data.
  | PUNPCKLWD = 447
  /// Push Word, Doubleword or Quadword Onto the Stack.
  | PUSH = 448
  /// Push All General-Purpose Registers (word).
  | PUSHA = 449
  /// Push All General-Purpose Registers (doubleword).
  | PUSHAD = 450
  /// Push EFLAGS Register onto the Stack (16bits of EFLAGS).
  | PUSHF = 451
  /// Push EFLAGS Register onto the Stack (EFLAGS).
  | PUSHFD = 452
  /// Push EFLAGS Register onto the Stack (RFLAGS).
  | PUSHFQ = 453
  /// Logical Exclusive OR.
  | PXOR = 454
  /// Rotate x bits (CF, r/m(x)) left once.
  | RCL = 455
  /// Rotate x bits (CF, r/m(x)) right once.
  | RCR = 456
  /// Read FS Segment Base.
  | RDFSBASE = 457
  /// Read GS Segment Base.
  | RDGSBASE = 458
  /// Read from Model Specific Register.
  | RDMSR = 459
  /// Read Protection Key Rights for User Pages.
  | RDPKRU = 460
  /// Read Performance-Monitoring Counters.
  | RDPMC = 461
  /// Read Random Number.
  | RDRAND = 462
  /// Read Random SEED.
  | RDSEED = 463
  /// Read Time-Stamp Counter.
  | RDTSC = 464
  /// Read Time-Stamp Counter and Processor ID.
  | RDTSCP = 465
  /// Far return.
  | RETFar = 466
  /// Far return w/ immediate.
  | RETFarImm = 467
  /// Near return.
  | RETNear = 468
  /// Near return w/ immediate .
  | RETNearImm = 469
  /// Rotate x bits r/m(x) left once..
  | ROL = 470
  /// Rotate x bits r/m(x) right once.
  | ROR = 471
  /// Rotate right without affecting arithmetic flags.
  | RORX = 472
  /// Round Scalar Double Precision Floating-Point Values.
  | ROUNDSD = 473
  /// Resume from System Management Mode.
  | RSM = 474
  /// Store AH into Flags.
  | SAHF = 475
  /// Shift.
  | SAR = 476
  /// Shift arithmetic right.
  | SARX = 477
  /// Integer Subtraction with Borrow.
  | SBB = 478
  /// Scan String (byte).
  | SCASB = 479
  /// Scan String (doubleword).
  | SCASD = 480
  /// Scan String (quadword).
  | SCASQ = 481
  /// Scan String (word).
  | SCASW = 482
  /// Set byte if above (CF = 0 and ZF = 0).
  | SETA = 483
  /// Set byte if below (CF = 1).
  | SETB = 484
  /// Set byte if below or equal (CF = 1 or ZF = 1).
  | SETBE = 485
  /// Set byte if greater (ZF = 0 and SF = OF)..
  | SETG = 486
  /// Set byte if less (SF <> OF).
  | SETL = 487
  /// Set byte if less or equal (ZF = 1 or SF <> OF).
  | SETLE = 488
  /// Set byte if not below (CF = 0).
  | SETNB = 489
  /// Set byte if not less (SF = OF).
  | SETNL = 490
  /// Set byte if not overflow (OF = 0).
  | SETNO = 491
  /// Set byte if not parity (PF = 0).
  | SETNP = 492
  /// Set byte if not sign (SF = 0).
  | SETNS = 493
  /// Set byte if not zero (ZF = 0).
  | SETNZ = 494
  /// Set byte if overflow (OF = 1).
  | SETO = 495
  /// Set byte if parity (PF = 1).
  | SETP = 496
  /// Set byte if sign (SF = 1).
  | SETS = 497
  /// Set byte if sign (ZF = 1).
  | SETZ = 498
  /// Store Fence.
  | SFENCE = 499
  /// Store Global Descriptor Table Register.
  | SGDT = 500
  /// Shift.
  | SHL = 501
  /// Double Precision Shift Left.
  | SHLD = 502
  /// Shift logic left.
  | SHLX = 503
  /// Shift.
  | SHR = 504
  /// Double Precision Shift Right.
  | SHRD = 505
  /// Shift logic right.
  | SHRX = 506
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | SHUFPD = 507
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | SHUFPS = 508
  /// Store Interrupt Descriptor Table Register.
  | SIDT = 509
  /// Store Local Descriptor Table Register.
  | SLDT = 510
  /// Store Machine Status Word.
  | SMSW = 511
  /// Compute packed square roots of packed double-precision FP values.
  | SQRTPD = 512
  /// Compute square roots of packed single-precision floating-point values.
  | SQRTPS = 513
  /// Compute scalar square root of scalar double-precision FP values.
  | SQRTSD = 514
  /// Compute square root of scalar single-precision floating-point values.
  | SQRTSS = 515
  /// Set AC Flag in EFLAGS Register.
  | STAC = 516
  /// Set Carry Flag.
  | STC = 517
  /// Set Direction Flag.
  | STD = 518
  /// Set Interrupt Flag.
  | STI = 519
  /// Store MXCSR Register State.
  | STMXCSR = 520
  /// Store String (store AL).
  | STOSB = 521
  /// Store String (store EAX).
  | STOSD = 522
  /// Store String (store RAX).
  | STOSQ = 523
  /// Store String (store AX).
  | STOSW = 524
  /// Store Task Register.
  | STR = 525
  /// Subtract.
  | SUB = 526
  /// Subtract Packed Double-Precision Floating-Point Values.
  | SUBPD = 527
  /// Subtract Packed Single-Precision Floating-Point Values.
  | SUBPS = 528
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | SUBSD = 529
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | SUBSS = 530
  /// Swap GS Base Register.
  | SWAPGS = 531
  /// Fast System Call.
  | SYSCALL = 532
  /// Fast System Call.
  | SYSENTER = 533
  /// Fast Return from Fast System Call.
  | SYSEXIT = 534
  /// Return From Fast System Call.
  | SYSRET = 535
  /// Logical Compare.
  | TEST = 536
  /// Count the Number of Trailing Zero Bits.
  | TZCNT = 537
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | UCOMISD = 538
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | UCOMISS = 539
  /// Undefined Instruction (Raise invalid opcode exception).
  | UD2 = 540
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | UNPCKHPD = 541
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | UNPCKHPS = 542
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | UNPCKLPD = 543
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | UNPCKLPS = 544
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPD = 545
  /// Add Packed Double-Precision Floating-Point Values.
  | VADDPS = 546
  /// Add Scalar Double-Precision Floating-Point Values.
  | VADDSD = 547
  /// Add Scalar Single-Precision Floating-Point Values.
  | VADDSS = 548
  /// Bitwise Logical AND of Packed Double-Precision Floating-Point Values.
  | VANDNPD = 549
  /// Bitwise Logical AND of Packed Single-Precision Floating-Point Values.
  | VANDNPS = 550
  /// Bitwise Logical AND NOT of Packed Double-Precision Floating-Point Values.
  | VANDPD = 551
  /// Bitwise Logical AND NOT of Packed Single-Precision Floating-Point Values.
  | VANDPS = 552
  /// Broadcast 128 bits of int data in mem to low and high 128-bits in ymm1.
  | VBROADCASTI128 = 553
  /// Broadcast Floating-Point Data.
  | VBROADCASTSS = 554
  /// Compare Scalar Ordered Double-Precision FP Values and Set EFLAGS.
  | VCOMISD = 555
  /// Compare Scalar Ordered Single-Precision FP Values and Set EFLAGS.
  | VCOMISS = 556
  /// Convert Scalar Double-Precision FP Value to Integer.
  | VCVTSD2SI = 557
  /// Convert Dword Integer to Scalar Double-Precision FP Value.
  | VCVTSI2SD = 558
  /// Convert Dword Integer to Scalar Single-Precision FP Value.
  | VCVTSI2SS = 559
  /// Convert Scalar Single-Precision FP Value to Dword Integer.
  | VCVTSS2SI = 560
  /// Convert with Truncation Scalar Double-Precision FP Value to Signed.
  | VCVTTSD2SI = 561
  /// Convert with Truncation Scalar Single-Precision FP Value to Dword Integer.
  | VCVTTSS2SI = 562
  /// Divide Packed Double-Precision Floating-Point Values.
  | VDIVPD = 563
  /// Divide Packed Single-Precision Floating-Point Values.
  | VDIVPS = 564
  /// Divide Scalar Double-Precision Floating-Point Values.
  | VDIVSD = 565
  /// Divide Scalar Single-Precision Floating-Point Values.
  | VDIVSS = 566
  /// Verify a Segment for Reading.
  | VERR = 567
  /// Verify a Segment for Writing.
  | VERW = 568
  /// Insert Packed Integer Values.
  | VINSERTI128 = 569
  /// Load Unaligned Integer 128 Bits.
  | VLDDQU = 570
  /// Call to VM Monitor.
  | VMCALL = 571
  /// Clear Virtual-Machine Control Structure.
  | VMCLEAR = 572
  /// Invoke VM function.
  | VMFUNC = 573
  /// Launch Virtual Machine.
  | VMLAUNCH = 574
  /// Move Aligned Packed Double-Precision Floating-Point Values.
  | VMOVAPD = 575
  /// Move Aligned Packed Single-Precision Floating-Point Values.
  | VMOVAPS = 576
  /// Move Doubleword.
  | VMOVD = 577
  /// Move One Double-FP and Duplicate.
  | VMOVDDUP = 578
  /// Move Aligned Double Quadword.
  | VMOVDQA = 579
  /// Move Aligned Double Quadword.
  | VMOVDQA32 = 580
  /// Move Aligned Double Quadword.
  | VMOVDQA64 = 581
  /// Move Unaligned Double Quadword.
  | VMOVDQU = 582
  /// Move Unaligned Double Quadword.
  | VMOVDQU32 = 583
  /// Move Unaligned Double Quadword.
  | VMOVDQU64 = 584
  /// Move Packed Single-Precision Floating-Point Values High to Low.
  | VMOVHLPS = 585
  /// Move High Packed Double-Precision Floating-Point Value.
  | VMOVHPD = 586
  /// Move High Packed Single-Precision Floating-Point Values.
  | VMOVHPS = 587
  /// Move Packed Single-Precision Floating-Point Values Low to High.
  | VMOVLHPS = 588
  /// Move Low Packed Double-Precision Floating-Point Value.
  | VMOVLPD = 589
  /// Move Low Packed Single-Precision Floating-Point Values.
  | VMOVLPS = 590
  /// Extract Packed Double-Precision Floating-Point Sign Mask.
  | VMOVMSKPD = 591
  /// Extract Packed Single-Precision Floating-Point Sign Mask.
  | VMOVMSKPS = 592
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | VMOVNTDQ = 593
  /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPD = 594
  /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
  | VMOVNTPS = 595
  /// Move Quadword.
  | VMOVQ = 596
  /// Move Data from String to String (doubleword)..
  | VMOVSD = 597
  /// Move Packed Single-FP High and Duplicate.
  | VMOVSHDUP = 598
  /// Move Packed Single-FP Low and Duplicate.
  | VMOVSLDUP = 599
  /// Move Scalar Single-Precision Floating-Point Values.
  | VMOVSS = 600
  /// Move Unaligned Packed Double-Precision Floating-Point Values.
  | VMOVUPD = 601
  /// Move Unaligned Packed Single-Precision Floating-Point Values.
  | VMOVUPS = 602
  /// Load Pointer to Virtual-Machine Control Structure.
  | VMPTRLD = 603
  /// Store Pointer to Virtual-Machine Control Structure.
  | VMPTRST = 604
  /// Resume Virtual Machine.
  | VMRESUME = 605
  /// Multiply Packed Double-Precision Floating-Point Values.
  | VMULPD = 606
  /// Multiply Packed Single-Precision Floating-Point Values.
  | VMULPS = 607
  /// Multiply Scalar Double-Precision Floating-Point Values.
  | VMULSD = 608
  /// Multiply Scalar Single-Precision Floating-Point Values.
  | VMULSS = 609
  /// Leave VMX Operation.
  | VMXOFF = 610
  /// Enter VMX Operation.
  | VMXON = 611
  /// Bitwise Logical OR of Double-Precision Floating-Point Values.
  | VORPD = 612
  /// Bitwise Logical OR of Single-Precision Floating-Point Values.
  | VORPS = 613
  /// Packed Absolute Value (byte).
  | VPABSB = 614
  /// Packed Absolute Value (dword).
  | VPABSD = 615
  /// Packed Absolute Value (word).
  | VPABSW = 616
  /// Pack with Signed Saturation.
  | VPACKSSDW = 617
  /// Pack with Signed Saturation.
  | VPACKSSWB = 618
  /// Pack with Unsigned Saturation.
  | VPACKUSDW = 619
  /// Pack with Unsigned Saturation.
  | VPACKUSWB = 620
  /// Add Packed byte Integers.
  | VPADDB = 621
  /// Add Packed Doubleword Integers.
  | VPADDD = 622
  /// Add Packed Quadword Integers.
  | VPADDQ = 623
  /// Add Packed Signed Integers with Signed Saturation (byte).
  | VPADDSB = 624
  /// Add Packed Signed Integers with Signed Saturation (word).
  | VPADDSW = 625
  /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPADDUSB = 626
  /// Add Packed Unsigned Integers with Unsigned Saturation (word).
  | VPADDUSW = 627
  /// Add Packed word Integers.
  | VPADDW = 628
  /// Packed Align Right.
  | VPALIGNR = 629
  /// Logical AND.
  | VPAND = 630
  /// Logical AND NOT.
  | VPANDN = 631
  /// Average Packed Integers (byte).
  | VPAVGB = 632
  /// Average Packed Integers (word).
  | VPAVGW = 633
  /// Broadcast Integer Data.
  | VPBROADCASTB = 634
  /// Compare Packed Data for Equal (byte).
  | VPCMPEQB = 635
  /// Compare Packed Data for Equal (doubleword).
  | VPCMPEQD = 636
  /// Compare Packed Data for Equal (quadword).
  | VPCMPEQQ = 637
  /// Compare Packed Data for Equal (word).
  | VPCMPEQW = 638
  /// Packed Compare Explicit Length Strings, Return Index.
  | VPCMPESTRI = 639
  /// Packed Compare Explicit Length Strings, Return Mask.
  | VPCMPESTRM = 640
  /// Compare Packed Signed Integers for Greater Than (byte).
  | VPCMPGTB = 641
  /// Compare Packed Signed Integers for Greater Than (doubleword).
  | VPCMPGTD = 642
  /// Compare Packed Data for Greater Than (qword).
  | VPCMPGTQ = 643
  /// Compare Packed Signed Integers for Greater Than (word).
  | VPCMPGTW = 644
  /// Packed Compare Implicit Length Strings, Return Index.
  | VPCMPISTRI = 645
  /// Packed Compare Implicit Length Strings, Return Mask.
  | VPCMPISTRM = 646
  /// Extract Word.
  | VPEXTRW = 647
  /// Packed Horizontal Add (32-bit).
  | VPHADDD = 648
  /// Packed Horizontal Add and Saturate (16-bit).
  | VPHADDSW = 649
  /// Packed Horizontal Add (16-bit).
  | VPHADDW = 650
  /// Packed Horizontal Word Minimum.
  | VPHMINPOSUW = 651
  /// Packed Horizontal Subtract (32-bit).
  | VPHSUBD = 652
  /// Packed Horizontal Subtract and Saturate (16-bit)
  | VPHSUBSW = 653
  /// Packed Horizontal Subtract (16-bit).
  | VPHSUBW = 654
  /// Insert Byte.
  | VPINSRB = 655
  /// Insert Word.
  | VPINSRW = 656
  /// Multiply and Add Packed Integers.
  | VPMADDWD = 657
  /// Maximum of Packed Signed Integers (byte).
  | VPMAXSB = 658
  /// Maximum of Packed Signed Integers (dword).
  | VPMAXSD = 659
  /// Maximum of Packed Signed Word Integers.
  | VPMAXSW = 660
  /// Maximum of Packed Unsigned Byte Integers.
  | VPMAXUB = 661
  /// Maximum of Packed Unsigned Integers (dword).
  | VPMAXUD = 662
  /// Maximum of Packed Unsigned Integers (word).
  | VPMAXUW = 663
  /// Minimum of Packed Signed Integers (byte).
  | VPMINSB = 664
  /// Minimum of Packed Signed Integers (dword).
  | VPMINSD = 665
  /// Minimum of Packed Signed Word Integers.
  | VPMINSW = 666
  /// Minimum of Packed Unsigned Byte Integers.
  | VPMINUB = 667
  /// Minimum of Packed Dword Integers.
  | VPMINUD = 668
  /// Minimum of Packed Unsigned Integers (word).
  | VPMINUW = 669
  /// Move Byte Mask.
  | VPMOVMSKB = 670
  /// Packed Move with Sign Extend (8-bit to 32-bit).
  | VPMOVSXBD = 671
  /// Packed Move with Sign Extend (8-bit to 64-bit).
  | VPMOVSXBQ = 672
  /// Packed Move with Sign Extend (8-bit to 16-bit).
  | VPMOVSXBW = 673
  /// Packed Move with Sign Extend (32-bit to 64-bit).
  | VPMOVSXDQ = 674
  /// Packed Move with Sign Extend (16-bit to 32-bit).
  | VPMOVSXWD = 675
  /// Packed Move with Sign Extend (16-bit to 64-bit).
  | VPMOVSXWQ = 676
  /// Packed Move with Zero Extend (8-bit to 32-bit).
  | VPMOVZXBD = 677
  /// Packed Move with Zero Extend (8-bit to 64-bit).
  | VPMOVZXBQ = 678
  /// Packed Move with Zero Extend (8-bit to 16-bit).
  | VPMOVZXBW = 679
  /// Packed Move with Zero Extend (32-bit to 64-bit).
  | VPMOVZXDQ = 680
  /// Packed Move with Zero Extend (16-bit to 32-bit).
  | VPMOVZXWD = 681
  /// Packed Move with Zero Extend (16-bit to 64-bit).
  | VPMOVZXWQ = 682
  /// Multiply Packed Doubleword Integers.
  | VPMULDQ = 683
  /// Packed Multiply High with Round and Scale.
  | VPMULHRSW = 684
  /// Multiply Packed Unsigned Integers and Store High Result.
  | VPMULHUW = 685
  /// Multiply Packed Signed Integers and Store High Result.
  | VPMULHW = 686
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLD = 687
  /// Multiply Packed Signed Integers and Store Low Result.
  | VPMULLW = 688
  /// Multiply Packed Unsigned Doubleword Integers.
  | VPMULUDQ = 689
  /// Bitwise Logical OR.
  | VPOR = 690
  /// Compute Sum of Absolute Differences.
  | VPSADBW = 691
  /// Packed Shuffle Bytes.
  | VPSHUFB = 692
  /// Shuffle Packed Doublewords.
  | VPSHUFD = 693
  /// Shuffle Packed High Words.
  | VPSHUFHW = 694
  /// Shuffle Packed Low Words.
  | VPSHUFLW = 695
  /// Packed SIGN (byte).
  | VPSIGNB = 696
  /// Packed SIGN (doubleword).
  | VPSIGND = 697
  /// Packed SIGN (word).
  | VPSIGNW = 698
  /// Shift Packed Data Left Logical (doubleword).
  | VPSLLD = 699
  /// Shift Double Quadword Left Logical.
  | VPSLLDQ = 700
  /// Shift Packed Data Left Logical (quadword).
  | VPSLLQ = 701
  /// Shift Packed Data Left Logical (word).
  | VPSLLW = 702
  /// Shift Packed Data Right Arithmetic (doubleword).
  | VPSRAD = 703
  /// Shift Packed Data Right Arithmetic (word).
  | VPSRAW = 704
  /// Shift Packed Data Right Logical (doubleword).
  | VPSRLD = 705
  /// Shift Double Quadword Right Logical.
  | VPSRLDQ = 706
  /// Shift Packed Data Right Logical (quadword).
  | VPSRLQ = 707
  /// Shift Packed Data Right Logical (word).
  | VPSRLW = 708
  /// Subtract Packed Integers (byte).
  | VPSUBB = 709
  /// Subtract Packed Integers (doubleword).
  | VPSUBD = 710
  /// Subtract Packed Integers (quadword).
  | VPSUBQ = 711
  /// Subtract Packed Signed Integers with Signed Saturation (byte).
  | VPSUBSB = 712
  /// Subtract Packed Signed Integers with Signed Saturation (word).
  | VPSUBSW = 713
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
  | VPSUBUSB = 714
  /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
  | VPSUBUSW = 715
  /// Subtract Packed Integers (word).
  | VPSUBW = 716
  /// Logical Compare.
  | VPTEST = 717
  /// Unpack High Data.
  | VPUNPCKHBW = 718
  /// Unpack High Data.
  | VPUNPCKHDQ = 719
  /// Unpack High Data.
  | VPUNPCKHQDQ = 720
  /// Unpack High Data.
  | VPUNPCKHWD = 721
  /// Unpack Low Data.
  | VPUNPCKLBW = 722
  /// Unpack Low Data.
  | VPUNPCKLDQ = 723
  /// Unpack Low Data.
  | VPUNPCKLQDQ = 724
  /// Unpack Low Data.
  | VPUNPCKLWD = 725
  /// Logical Exclusive OR.
  | VPXOR = 726
  /// Shuffle Packed Double-Precision Floating-Point Values.
  | VSHUFPD = 727
  /// Shuffle Packed Single-Precision Floating-Point Values.
  | VSHUFPS = 728
  /// Compute packed square roots of packed double-precision FP values.
  | VSQRTPD = 729
  /// Compute square roots of packed single-precision floating-point values.
  | VSQRTPS = 730
  /// Compute scalar square root of scalar double-precision FP values.
  | VSQRTSD = 731
  /// Compute square root of scalar single-precision floating-point values.
  | VSQRTSS = 732
  /// Subtract Packed Double-Precision Floating-Point Values.
  | VSUBPD = 733
  /// Subtract Packed Single-Precision Floating-Point Values.
  | VSUBPS = 734
  /// Subtract Scalar Double-Precision Floating-Point Values.
  | VSUBSD = 735
  /// Subtract Scalar Single-Precision Floating-Point Values.
  | VSUBSS = 736
  /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
  | VUCOMISD = 737
  /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
  | VUCOMISS = 738
  /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
  | VUNPCKHPD = 739
  /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
  | VUNPCKHPS = 740
  /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
  | VUNPCKLPD = 741
  /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
  | VUNPCKLPS = 742
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | VXORPD = 743
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | VXORPS = 744
  /// Zero Upper Bits of YMM Registers.
  | VZEROUPPER = 745
  /// Wait.
  | WAIT = 746
  /// Write Back and Invalidate Cache.
  | WBINVD = 747
  /// Write FS Segment Base.
  | WRFSBASE = 748
  /// Write GS Segment Base.
  | WRGSBASE = 749
  /// Write to Model Specific Register.
  | WRMSR = 750
  /// Write Data to User Page Key Register.
  | WRPKRU = 751
  /// Transactional Abort.
  | XABORT = 752
  /// Exchange and Add.
  | XADD = 753
  /// Transactional Begin.
  | XBEGIN = 754
  /// Exchange Register/Memory with Register.
  | XCHG = 755
  /// Transactional End.
  | XEND = 756
  /// Value of Extended Control Register.
  | XGETBV = 757
  /// Table Look-up Translation.
  | XLATB = 758
  /// Logical Exclusive OR.
  | XOR = 759
  /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
  | XORPD = 760
  /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
  | XORPS = 761
  /// Restore Processor Extended States.
  | XRSTOR = 762
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS = 763
  /// Restore processor supervisor-mode extended states from memory.
  | XRSTORS64 = 764
  /// Save Processor Extended States.
  | XSAVE = 765
  /// Save processor extended states with compaction to memory.
  | XSAVEC = 766
  /// Save processor extended states with compaction to memory.
  | XSAVEC64 = 767
  /// Save Processor Extended States Optimized.
  | XSAVEOPT = 768
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES = 769
  /// Save processor supervisor-mode extended states to memory.
  | XSAVES64 = 770
  /// Set Extended Control Register.
  | XSETBV = 771
  /// Test If In Transactional Execution.
  | XTEST = 772
  /// Invalid Opcode.
  | InvalOP = 773

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
  | GoToLabel of string
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
