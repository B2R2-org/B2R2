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
    /// Conditional Move (Move if less (SF≠ OF)).
    | CMOVL = 42
    /// Conditional Move (Move if less or equal (ZF=1 or SF≠ OF)).
    | CMOVLE = 43
    /// Conditional Move (Move if greater or equal (SF=OF)).
    | CMOVGE = 44
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
    /// Compare String Operands (word).
    | CMPSW = 55
    /// Compare String Operands (dword).
    | CMPSD = 56
    /// Compare String Operands (quadword).
    | CMPSQ = 57
    /// Compare and Exchange Bytes.
    | CMPXCH8B = 58
    /// Compare and Exchange.
    | CMPXCHG = 59
    /// Compare and Exchange Bytes.
    | CMPXCHG16B = 60
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
    /// Load Integer.
    | FILD = 128
    /// Multiply.
    | FIMUL = 129
    /// Increment Stack-Top Pointer.
    | FINCSTP = 130
    /// Initialize Floating-Point Unit.
    | FINIT = 131
    /// Compare Integer.
    | FICOM = 132
    /// Compare Integer and pop the register stack.
    | FICOMP = 133
    /// Store Integer.
    | FIST = 134
    /// Store Integer and pop the register stack.
    | FISTP = 135
    /// Store Integer with Truncation.
    | FISTTP = 136
    /// Subtract.
    | FISUB = 137
    /// Reverse Subtract.
    | FISUBR = 138
    /// Divide
    | FIDIV = 139
    /// Reverse Divide.
    | FIDIVR = 140
    /// Load Floating Point Value.
    | FLD = 141
    /// Load Constant (Push +1.0 onto the FPU register stack).
    | FLD1 = 142
    /// Load x87 FPU Control Word.
    | FLDCW = 143
    /// Load x87 FPU Environment.
    | FLDENV = 144
    /// Load Constant (Push log210 onto the FPU register stack).
    | FLDL2T = 145
    /// Load Constant (Push log2e onto the FPU register stack).
    | FLDL2E = 146
    /// Load Constant (Push Pi onto the FPU register stack).
    | FLDPI = 147
    /// Load Constant (Push log102 onto the FPU register stack).
    | FLDLG2 = 148
    /// Load Constant (Push loge2 onto the FPU register stack).
    | FLDLN2 = 149
    /// Load Constant (Push +0.0 onto the FPU register stack).
    | FLDZ = 150
    /// No Operation.
    | FNOP = 151
    /// Multiply.
    | FMUL = 152
    /// Multiply and pop the register stack.
    | FMULP = 153
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
    /// Extract Exponent and Significand.
    | FXTRACT = 182
    /// compute y * log2x.
    | FYL2X = 183
    /// compute y * log2(x+1).
    | FYL2XP1 = 184
    /// Restore x87 FPU, MMX, XMM, and MXCSR State.
    | FXRSTOR = 185
    /// Restore x87 FPU, MMX, XMM, and MXCSR State.
    | FXRSTOR64 = 186
    /// Save x87 FPU, MMX Technology, and SSE State.
    | FXSAVE = 187
    /// Save x87 FPU, MMX Technology, and SSE State.
    | FXSAVE64 = 188
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
    /// Call to Interrupt (Interrupt 3—trap to debugger).
    | INT3 = 200
    /// Call to Interrupt (InteInterrupt 4—if overflow flag is 1).
    | INTO = 201
    /// Invalidate Internal Caches.
    | INVD = 202
    /// Invalidate TLB Entries.
    | INVLPG = 203
    /// Interrupt return (16-bit operand size).
    | IRETW = 204
    /// Interrupt return (32-bit operand size).
    | IRETD = 205
    /// Interrupt return (64-bit operand size).
    | IRETQ = 206
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
    /// Jump if Condition Is Met (Jump short if less, SF≠ OF).
    | JL = 213
    /// Jump if Condition Is Met (Jump short if less or equal, ZF=1 or SF≠ OF).
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
    /// Jump if Condition Is Met (Jump short if zero, ZF = 1).
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
    /// Load String (word).
    | LODSW = 244
    /// Load String (doubleword).
    | LODSD = 245
    /// Load String (quadword).
    | LODSQ = 246
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
    /// Return Maximum Packed Single-Precision Floating-Point Values.
    | MAXPS = 254
    /// Return Maximum Packed Double-Precision Floating-Point Values.
    | MAXPD = 255
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
    /// Load Double Quadword Non-Temporal Aligned Hint
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
    /// Move Scalar Single-Precision Floating-Point Values.
    | MOVSS = 292
    /// Move Data from String to String (word).
    | MOVSW = 293
    /// Move Data from String to String (quadword).
    | MOVSQ = 294
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
    /// Pack with Signed Saturation.
    | PACKSSDW = 317
    /// Pack with Signed Saturation.
    | PACKSSWB = 318
    /// Pack with Unsigned Saturation.
    | PACKUSWB = 319
    /// Add Packed byte Integers.
    | PADDB = 320
    /// Add Packed Doubleword Integers.
    | PADDD = 321
    /// Add Packed Quadword Integers.
    | PADDQ = 322
    /// Add Packed Signed Integers with Signed Saturation (byte).
    | PADDSB = 323
    /// Add Packed Signed Integers with Signed Saturation (word).
    | PADDSW = 324
    /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
    | PADDUSB = 325
    /// Add Packed Unsigned Integers with Unsigned Saturation (word).
    | PADDUSW = 326
    /// Add Packed word Integers.
    | PADDW = 327
    /// Packed Align Right.
    | PALIGNR = 328
    /// Logical AND.
    | PAND = 329
    /// Logical AND NOT.
    | PANDN = 330
    /// Average Packed Integers (byte).
    | PAVGB = 331
    /// Average Packed Integers (word).
    | PAVGW = 332
    /// Spin Loop Hint.
    | PAUSE = 333
    /// Compare Packed Data for Equal (byte).
    | PCMPEQB = 334
    /// Compare Packed Data for Equal (doubleword).
    | PCMPEQD = 335
    /// Compare Packed Data for Equal (quadword).
    | PCMPEQQ = 336
    /// Packed Compare Explicit Length Strings, Return Index.
    | PCMPESTRI = 337
    /// Packed Compare Explicit Length Strings, Return Mask.
    | PCMPESTRM = 338
    /// Compare Packed Signed Integers for Greater Than (byte).
    | PCMPGTB = 339
    /// Compare Packed Signed Integers for Greater Than (doubleword).
    | PCMPGTD = 340
    /// Compare Packed Signed Integers for Greater Than (word).
    | PCMPGTW = 341
    /// Packed Compare Implicit Length Strings, Return Index.
    | PCMPISTRI = 342
    /// Packed Compare Implicit Length Strings, Return Mask.
    | PCMPISTRM = 343
    /// Extract Word.
    | PEXTRW = 344
    /// Insert Byte.
    | PINSRB = 345
    /// Insert Word.
    | PINSRW = 346
    /// Multiply and Add Packed Integers.
    | PMADDWD = 347
    /// Maximum of Packed Signed Word Integers.
    | PMAXSW = 348
    /// Maximum of Packed Unsigned Byte Integers.
    | PMAXUB = 349
    /// Minimum of Packed Signed Word Integers.
    | PMINSW = 350
    /// Minimum of Packed Unsigned Byte Integers.
    | PMINUB = 351
    /// Minimum of Packed Dword Integers.
    | PMINUD = 352
    /// Minimum of Packed Signed Byte Integers.
    | PMINSB = 353
    /// Move Byte Mask.
    | PMOVMSKB = 354
    /// Multiply Packed Unsigned Integers and Store High Result.
    | PMULHUW = 355
    /// Multiply Packed Signed Integers and Store High Result.
    | PMULHW = 356
    /// Multiply Packed Signed Integers and Store Low Result.
    | PMULLW = 357
    /// Multiply Packed Unsigned Doubleword Integers.
    | PMULUDQ = 358
    /// Pop a Value from the Stack.
    | POP = 359
    /// Pop All General-Purpose Registers (word).
    | POPA = 360
    /// Pop All General-Purpose Registers (doubleword).
    | POPAD = 361
    /// Return the Count of Number of Bits Set to 1.
    | POPCNT = 362
    /// Pop Stack into EFLAGS Register (lower 16bits EFLAGS).
    | POPF = 363
    /// Pop Stack into EFLAGS Register (EFLAGS).
    | POPFD = 364
    /// Pop Stack into EFLAGS Register (RFLAGS).
    | POPFQ = 365
    /// Bitwise Logical OR.
    | POR = 366
    /// Prefetch Data Into Caches (using NTA hint).
    | PREFETCHNTA = 367
    /// Prefetch Data Into Caches (using T0 hint).
    | PREFETCHT0 = 368
    /// Prefetch Data Into Caches (using T1 hint).
    | PREFETCHT1 = 369
    /// Prefetch Data Into Caches (using T2 hint).
    | PREFETCHT2 = 370
    /// Prefetch Data into Caches in Anticipation of a Write.
    | PREFETCHW = 371
    /// Prefetch Vector Data Into Caches with Intent to Write and T1 Hint.
    | PREFETCHWT1 = 372
    /// Compute Sum of Absolute Differences.
    | PSADBW = 373
    /// Packed Shuffle Bytes.
    | PSHUFB = 374
    /// Shuffle Packed Doublewords.
    | PSHUFD = 375
    /// Shuffle Packed High Words.
    | PSHUFHW = 376
    /// Shuffle Packed Low Words.
    | PSHUFLW = 377
    /// Shuffle Packed Words.
    | PSHUFW = 378
    /// Shift Packed Data Left Logical (doubleword).
    | PSLLD = 379
    /// Shift Double Quadword Left Logical.
    | PSLLDQ = 380
    /// Shift Packed Data Left Logical (quadword).
    | PSLLQ = 381
    /// Shift Packed Data Left Logical (word).
    | PSLLW = 382
    /// Shift Packed Data Right Arithmetic (doubleword).
    | PSRAD = 383
    /// Shift Packed Data Right Arithmetic (word).
    | PSRAW = 384
    /// Shift Packed Data Right Logical (doubleword).
    | PSRLD = 385
    /// Shift Double Quadword Right Logical.
    | PSRLDQ = 386
    /// Shift Packed Data Right Logical (quadword).
    | PSRLQ = 387
    /// Shift Packed Data Right Logical (word).
    | PSRLW = 388
    /// Subtract Packed Integers (byte).
    | PSUBB = 389
    /// Subtract Packed Integers (doubleword).
    | PSUBD = 390
    /// Subtract Packed Integers (quadword).
    | PSUBQ = 391
    /// Subtract Packed Signed Integers with Signed Saturation (byte).
    | PSUBSB = 392
    /// Subtract Packed Signed Integers with Signed Saturation (word).
    | PSUBSW = 393
    /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
    | PSUBUSB = 394
    /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
    | PSUBUSW = 395
    /// Subtract Packed Integers (word).
    | PSUBW = 396
    /// Logical Compare.
    | PTEST = 397
    /// Unpack High Data.
    | PUNPCKHBW = 398
    /// Unpack High Data.
    | PUNPCKHDQ = 399
    /// Unpack High Data.
    | PUNPCKHQDQ = 400
    /// Unpack High Data.
    | PUNPCKHWD = 401
    /// Unpack Low Data.
    | PUNPCKLBW = 402
    /// Unpack Low Data.
    | PUNPCKLDQ = 403
    /// Unpack Low Data.
    | PUNPCKLQDQ = 404
    /// Unpack Low Data.
    | PUNPCKLWD = 405
    /// Push Word, Doubleword or Quadword Onto the Stack.
    | PUSH = 406
    /// Push All General-Purpose Registers (word).
    | PUSHA = 407
    /// Push All General-Purpose Registers (doubleword).
    | PUSHAD = 408
    /// Push EFLAGS Register onto the Stack (16bits of EFLAGS).
    | PUSHF = 409
    /// Push EFLAGS Register onto the Stack (EFLAGS).
    | PUSHFD = 410
    /// Push EFLAGS Register onto the Stack (RFLAGS).
    | PUSHFQ = 411
    /// Logical Exclusive OR.
    | PXOR = 412
    /// Rotate x bits (CF, r/m(x)) left once.
    | RCL = 413
    /// Rotate x bits (CF, r/m(x)) right once.
    | RCR = 414
    /// Read FS Segment Base.
    | RDFSBASE = 415
    /// Read GS Segment Base.
    | RDGSBASE = 416
    /// Read from Model Specific Register.
    | RDMSR = 417
    /// Read Protection Key Rights for User Pages.
    | RDPKRU = 418
    /// Read Performance-Monitoring Counters.
    | RDPMC = 419
    /// Read Random Number.
    | RDRAND = 420
    /// Read Random SEED.
    | RDSEED = 421
    /// Read Time-Stamp Counter.
    | RDTSC = 422
    /// Read Time-Stamp Counter and Processor ID.
    | RDTSCP = 423
    /// Near return.
    | RETNear = 424
    /// Near return w/ immediate .
    | RETNearImm = 425
    /// Far return.
    | RETFar = 426
    /// Far return w/ immediate.
    | RETFarImm = 427
    /// Rotate x bits r/m(x) left once..
    | ROL = 428
    /// Rotate x bits r/m(x) right once.
    | ROR = 429
    /// Round Scalar Double Precision Floating-Point Values.
    | ROUNDSD = 430
    /// Resume from System Management Mode.
    | RSM = 431
    /// Store AH into Flags.
    | SAHF = 432
    /// Shift.
    | SAR = 433
    /// Integer Subtraction with Borrow.
    | SBB = 434
    /// Scan String (byte).
    | SCASB = 435
    /// Scan String (word).
    | SCASW = 436
    /// Scan String (doubleword).
    | SCASD = 437
    /// Scan String (quadword).
    | SCASQ = 438
    /// Set byte if above (CF=0 and ZF=0).
    | SETA = 439
    /// Set byte if below (CF=1).
    | SETB = 440
    /// Set byte if below or equal (CF=1 or ZF=1).
    | SETBE = 441
    /// Set byte if greater (ZF=0 and SF=OF)..
    | SETG = 442
    /// Set byte if less (SF≠ OF).
    | SETL = 443
    /// Set byte if less or equal (ZF=1 or SF≠ OF).
    | SETLE = 444
    /// Set byte if not below (CF=0).
    | SETNB = 445
    /// Set byte if not less (SF=OF).
    | SETNL = 446
    /// Set byte if not overflow (OF=0).
    | SETNO = 447
    /// Set byte if not parity (PF=0).
    | SETNP = 448
    /// Set byte if not sign (SF=0).
    | SETNS = 449
    /// Set byte if not zero (ZF=0).
    | SETNZ = 450
    /// Set byte if overflow (OF=1).
    | SETO = 451
    /// Set byte if parity (PF=1).
    | SETP = 452
    /// Set byte if sign (SF=1).
    | SETS = 453
    /// Set byte if sign (ZF=1).
    | SETZ = 454
    /// Store Fence.
    | SFENCE = 455
    /// Store Global Descriptor Table Register.
    | SGDT = 456
    /// Shift.
    | SHL = 457
    /// Double Precision Shift Left.
    | SHLD = 458
    /// Shift.
    | SHR = 459
    /// Double Precision Shift Right.
    | SHRD = 460
    /// Shuffle Packed Double-Precision Floating-Point Values.
    | SHUFPD = 461
    /// Shuffle Packed Single-Precision Floating-Point Values.
    | SHUFPS = 462
    /// Store Interrupt Descriptor Table Register.
    | SIDT = 463
    /// Store Local Descriptor Table Register.
    | SLDT = 464
    /// Store Machine Status Word.
    | SMSW = 465
    /// Set AC Flag in EFLAGS Register.
    | STAC = 466
    /// Set Carry Flag.
    | STC = 467
    /// Set Direction Flag.
    | STD = 468
    /// Set Interrupt Flag.
    | STI = 469
    /// Store MXCSR Register State.
    | STMXCSR = 470
    /// Store String (store AL).
    | STOSB = 471
    /// Store String (store AX).
    | STOSW = 472
    /// Store String (store EAX).
    | STOSD = 473
    /// Store String (store RAX).
    | STOSQ = 474
    /// Store Task Register.
    | STR = 475
    /// Subtract.
    | SUB = 476
    /// Subtract Packed Double-Precision Floating-Point Values.
    | SUBPD = 477
    /// Subtract Packed Single-Precision Floating-Point Values.
    | SUBPS = 478
    /// Subtract Scalar Double-Precision Floating-Point Values.
    | SUBSD = 479
    /// Subtract Scalar Single-Precision Floating-Point Values.
    | SUBSS = 480
    /// Swap GS Base Register.
    | SWAPGS = 481
    /// Fast System Call.
    | SYSCALL = 482
    /// Fast System Call.
    | SYSENTER = 483
    /// Fast Return from Fast System Call.
    | SYSEXIT = 484
    /// Return From Fast System Call.
    | SYSRET = 485
    /// Logical Compare.
    | TEST = 486
    /// Count the Number of Trailing Zero Bits.
    | TZCNT = 487
    /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
    | UCOMISD = 488
    /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
    | UCOMISS = 489
    /// Undefined Instruction (Raise invalid opcode exception).
    | UD2 = 490
    /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
    | UNPCKHPD = 491
    /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
    | UNPCKHPS = 492
    /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
    | UNPCKLPD = 493
    /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
    | UNPCKLPS = 494
    /// Add Packed Double-Precision Floating-Point Values.
    | VADDPD = 495
    /// Add Packed Double-Precision Floating-Point Values.
    | VADDPS = 496
    /// Add Scalar Double-Precision Floating-Point Values.
    | VADDSD = 497
    /// Add Scalar Single-Precision Floating-Point Values.
    | VADDSS = 498
    /// Bitwise Logical AND of Packed Double-Precision Floating-Point Values.
    | VANDNPD = 499
    /// Bitwise Logical AND of Packed Single-Precision Floating-Point Values.
    | VANDNPS = 500
    /// Bitwise Logical AND NOT of Packed Double-Precision Floating-Point Values.
    | VANDPD = 501
    /// Bitwise Logical AND NOT of Packed Single-Precision Floating-Point Values.
    | VANDPS = 502
    /// Broadcast Floating-Point Data.
    | VBROADCASTSS = 503
    /// Compare Scalar Ordered Double-Precision FP Values and Set EFLAGS.
    | VCOMISD = 504
    /// Compare Scalar Ordered Single-Precision FP Values and Set EFLAGS.
    | VCOMISS = 505
    /// Convert Scalar Double-Precision FP Value to Integer.
    | VCVTSD2SI = 506
    /// Convert Dword Integer to Scalar Double-Precision FP Value.
    | VCVTSI2SD = 507
    /// Convert Dword Integer to Scalar Single-Precision FP Value.
    | VCVTSI2SS = 508
    /// Convert Scalar Single-Precision FP Value to Dword Integer.
    | VCVTSS2SI = 509
    /// Convert with Truncation Scalar Double-Precision FP Value to Signed.
    | VCVTTSD2SI = 510
    /// Convert with Truncation Scalar Single-Precision FP Value to Dword Integer.
    | VCVTTSS2SI = 511
    /// Divide Packed Double-Precision Floating-Point Values.
    | VDIVPD = 512
    /// Divide Packed Single-Precision Floating-Point Values.
    | VDIVPS = 513
    /// Divide Scalar Double-Precision Floating-Point Values.
    | VDIVSD = 514
    /// Divide Scalar Single-Precision Floating-Point Values.
    | VDIVSS = 515
    /// Verify a Segment for Reading.
    | VERR = 516
    /// Verify a Segment for Writing.
    | VERW = 517
    /// Insert Packed Integer Values.
    | VINSERTI128 = 518
    /// Load Unaligned Integer 128 Bits.
    | VLDDQU = 519
    /// Call to VM Monitor.
    | VMCALL = 520
    /// Clear Virtual-Machine Control Structure.
    | VMCLEAR = 521
    /// Invoke VM function.
    | VMFUNC = 522
    /// Launch Virtual Machine.
    | VMLAUNCH = 523
    /// Move Aligned Packed Double-Precision Floating-Point Values.
    | VMOVAPD = 524
    /// Move Aligned Packed Single-Precision Floating-Point Values.
    | VMOVAPS = 525
    /// Move Doubleword.
    | VMOVD = 526
    /// Move One Double-FP and Duplicate.
    | VMOVDDUP = 527
    /// Move Aligned Double Quadword.
    | VMOVDQA = 528
    /// Move Aligned Double Quadword.
    | VMOVDQA32 = 529
    /// Move Aligned Double Quadword.
    | VMOVDQA64 = 530
    /// Move Unaligned Double Quadword.
    | VMOVDQU = 531
    /// Move Unaligned Double Quadword.
    | VMOVDQU32 = 532
    /// Move Unaligned Double Quadword.
    | VMOVDQU64 = 533
    /// Move Packed Single-Precision Floating-Point Values High to Low.
    | VMOVHLPS = 534
    /// Move High Packed Double-Precision Floating-Point Value.
    | VMOVHPD = 535
    /// Move High Packed Single-Precision Floating-Point Values.
    | VMOVHPS = 536
    /// Move Packed Single-Precision Floating-Point Values Low to High.
    | VMOVLHPS = 537
    /// Move Low Packed Double-Precision Floating-Point Value.
    | VMOVLPD = 538
    /// Move Low Packed Single-Precision Floating-Point Values.
    | VMOVLPS = 539
    /// Extract Packed Double-Precision Floating-Point Sign Mask.
    | VMOVMSKPD = 540
    /// Extract Packed Single-Precision Floating-Point Sign Mask.
    | VMOVMSKPS = 541
    /// Load Double Quadword Non-Temporal Aligned Hint.
    | VMOVNTDQ = 542
    /// Store Packed Double-Precision FP Values Using Non-Temporal Hint.
    | VMOVNTPD = 543
    /// Store Packed Single-Precision FP Values Using Non-Temporal Hint.
    | VMOVNTPS = 544
    /// Move Quadword.
    | VMOVQ = 545
    /// Move Data from String to String (doubleword)..
    | VMOVSD = 546
    /// Move Packed Single-FP High and Duplicate.
    | VMOVSHDUP = 547
    /// Move Packed Single-FP Low and Duplicate.
    | VMOVSLDUP = 548
    /// Move Scalar Single-Precision Floating-Point Values.
    | VMOVSS = 549
    /// Move Unaligned Packed Double-Precision Floating-Point Values.
    | VMOVUPD = 550
    /// Move Unaligned Packed Single-Precision Floating-Point Values.
    | VMOVUPS = 551
    /// Load Pointer to Virtual-Machine Control Structure.
    | VMPTRLD = 552
    /// Store Pointer to Virtual-Machine Control Structure.
    | VMPTRST = 553
    /// Resume Virtual Machine.
    | VMRESUME = 554
    /// Multiply Packed Double-Precision Floating-Point Values.
    | VMULPD = 555
    /// Multiply Packed Single-Precision Floating-Point Values.
    | VMULPS = 556
    /// Multiply Scalar Double-Precision Floating-Point Values.
    | VMULSD = 557
    /// Multiply Scalar Single-Precision Floating-Point Values.
    | VMULSS = 558
    /// Leave VMX Operation.
    | VMXOFF = 559
    /// Enter VMX Operation.
    | VMXON = 560
    /// Bitwise Logical OR of Double-Precision Floating-Point Values.
    | VORPD = 561
    /// Bitwise Logical OR of Single-Precision Floating-Point Values.
    | VORPS = 562
    /// Pack with Signed Saturation.
    | VPACKSSDW = 563
    /// Pack with Signed Saturation.
    | VPACKSSWB = 564
    /// Pack with Unsigned Saturation.
    | VPACKUSWB = 565
    /// Add Packed byte Integers.
    | VPADDB = 566
    /// Add Packed Doubleword Integers.
    | VPADDD = 567
    /// Add Packed Quadword Integers.
    | VPADDQ = 568
    /// Add Packed Signed Integers with Signed Saturation (byte).
    | VPADDSB = 569
    /// Add Packed Signed Integers with Signed Saturation (word).
    | VPADDSW = 570
    /// Add Packed Unsigned Integers with Unsigned Saturation (byte).
    | VPADDUSB = 571
    /// Add Packed Unsigned Integers with Unsigned Saturation (word).
    | VPADDUSW = 572
    /// Add Packed word Integers.
    | VPADDW = 573
    /// Packed Align Right.
    | VPALIGNR = 574
    /// Logical AND.
    | VPAND = 575
    /// Logical AND NOT.
    | VPANDN = 576
    /// Average Packed Integers (byte).
    | VPAVGB = 577
    /// Average Packed Integers (word).
    | VPAVGW = 578
    /// Broadcast Integer Data.
    | VPBROADCASTB = 579
    /// Compare Packed Data for Equal (byte).
    | VPCMPEQB = 580
    /// Compare Packed Data for Equal (doubleword).
    | VPCMPEQD = 581
    /// Compare Packed Data for Equal (quadword).
    | VPCMPEQQ = 582
    /// Packed Compare Explicit Length Strings, Return Index.
    | VPCMPESTRI = 583
    /// Packed Compare Explicit Length Strings, Return Mask.
    | VPCMPESTRM = 584
    /// Compare Packed Signed Integers for Greater Than (byte).
    | VPCMPGTB = 585
    /// Compare Packed Signed Integers for Greater Than (doubleword).
    | VPCMPGTD = 586
    /// Compare Packed Signed Integers for Greater Than (word).
    | VPCMPGTW = 587
    /// Packed Compare Implicit Length Strings, Return Index.
    | VPCMPISTRI = 588
    /// Packed Compare Implicit Length Strings, Return Mask.
    | VPCMPISTRM = 589
    /// Extract Word.
    | VPEXTRW = 590
    /// Insert Byte.
    | VPINSRB = 591
    /// Insert Word.
    | VPINSRW = 592
    /// Multiply and Add Packed Integers.
    | VPMADDWD = 593
    /// Maximum of Packed Signed Word Integers.
    | VPMAXSW = 594
    /// Maximum of Packed Unsigned Byte Integers.
    | VPMAXUB = 595
    /// Minimum of Packed Signed Word Integers.
    | VPMINSW = 596
    /// Minimum of Packed Unsigned Byte Integers.
    | VPMINUB = 597
    /// Minimum of Packed Dword Integers.
    | VPMINUD = 598
    /// Move Byte Mask.
    | VPMOVMSKB = 599
    /// Multiply Packed Unsigned Integers and Store High Result.
    | VPMULHUW = 600
    /// Multiply Packed Signed Integers and Store High Result.
    | VPMULHW = 601
    /// Multiply Packed Signed Integers and Store Low Result.
    | VPMULLW = 602
    /// Multiply Packed Unsigned Doubleword Integers.
    | VPMULUDQ = 603
    /// Bitwise Logical OR.
    | VPOR = 604
    /// Compute Sum of Absolute Differences.
    | VPSADBW = 605
    /// Packed Shuffle Bytes.
    | VPSHUFB = 606
    /// Shuffle Packed Doublewords.
    | VPSHUFD = 607
    /// Shuffle Packed High Words.
    | VPSHUFHW = 608
    /// Shuffle Packed Low Words.
    | VPSHUFLW = 609
    /// Shift Packed Data Left Logical (doubleword).
    | VPSLLD = 610
    /// Shift Double Quadword Left Logical.
    | VPSLLDQ = 611
    /// Shift Packed Data Left Logical (quadword).
    | VPSLLQ = 612
    /// Shift Packed Data Left Logical (word).
    | VPSLLW = 613
    /// Shift Packed Data Right Arithmetic (doubleword).
    | VPSRAD = 614
    /// Shift Packed Data Right Arithmetic (word).
    | VPSRAW = 615
    /// Shift Packed Data Right Logical (doubleword).
    | VPSRLD = 616
    /// Shift Double Quadword Right Logical.
    | VPSRLDQ = 617
    /// Shift Packed Data Right Logical (quadword).
    | VPSRLQ = 618
    /// Shift Packed Data Right Logical (word).
    | VPSRLW = 619
    /// Subtract Packed Integers (byte).
    | VPSUBB = 620
    /// Subtract Packed Integers (doubleword).
    | VPSUBD = 621
    /// Subtract Packed Integers (quadword).
    | VPSUBQ = 622
    /// Subtract Packed Signed Integers with Signed Saturation (byte).
    | VPSUBSB = 623
    /// Subtract Packed Signed Integers with Signed Saturation (word).
    | VPSUBSW = 624
    /// Subtract Packed Unsigned Integers with Unsigned Saturation (byte).
    | VPSUBUSB = 625
    /// Subtract Packed Unsigned Integers with Unsigned Saturation (word).
    | VPSUBUSW = 626
    /// Subtract Packed Integers (word).
    | VPSUBW = 627
    /// Logical Compare.
    | VPTEST = 628
    /// Unpack High Data.
    | VPUNPCKHBW = 629
    /// Unpack High Data.
    | VPUNPCKHDQ = 630
    /// Unpack High Data.
    | VPUNPCKHQDQ = 631
    /// Unpack High Data.
    | VPUNPCKHWD = 632
    /// Unpack Low Data.
    | VPUNPCKLBW = 633
    /// Unpack Low Data.
    | VPUNPCKLDQ = 634
    /// Unpack Low Data.
    | VPUNPCKLQDQ = 635
    /// Unpack Low Data.
    | VPUNPCKLWD = 636
    /// Logical Exclusive OR.
    | VPXOR = 637
    /// Shuffle Packed Double-Precision Floating-Point Values.
    | VSHUFPD = 638
    /// Shuffle Packed Single-Precision Floating-Point Values.
    | VSHUFPS = 639
    /// Subtract Packed Double-Precision Floating-Point Values.
    | VSUBPD = 640
    /// Subtract Packed Single-Precision Floating-Point Values.
    | VSUBPS = 641
    /// Subtract Scalar Double-Precision Floating-Point Values.
    | VSUBSD = 642
    /// Subtract Scalar Single-Precision Floating-Point Values.
    | VSUBSS = 643
    /// Unordered Compare Scalar Double-Precision FP Values and Set EFLAGS.
    | VUCOMISD = 644
    /// Unordered Compare Scalar Single-Precision FPValues and Set EFLAGS.
    | VUCOMISS = 645
    /// Unpack and Interleave High Packed Double-Precision Floating-Point Values.
    | VUNPCKHPD = 646
    /// Unpack and Interleave High Packed Single-Precision Floating-Point Values.
    | VUNPCKHPS = 647
    /// Unpack and Interleave Low Packed Double-Precision Floating-Point Values.
    | VUNPCKLPD = 648
    /// Unpack and Interleave Low Packed Single-Precision Floating-Point Values.
    | VUNPCKLPS = 649
    /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
    | VXORPD = 650
    /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
    | VXORPS = 651
    /// Zero Upper Bits of YMM Registers.
    | VZEROUPPER = 652
    /// Wait.
    | WAIT = 653
    /// Write Back and Invalidate Cache.
    | WBINVD = 654
    /// Write FS Segment Base.
    | WRFSBASE = 655
    /// Write GS Segment Base.
    | WRGSBASE = 656
    /// Write to Model Specific Register.
    | WRMSR = 657
    /// Write Data to User Page Key Register.
    | WRPKRU = 658
    /// Transactional Abort.
    | XABORT = 659
    /// Exchange and Add.
    | XADD = 660
    /// Transactional Begin.
    | XBEGIN = 661
    /// Exchange Register/Memory with Register.
    | XCHG = 662
    /// Transactional End.
    | XEND = 663
    /// Value of Extended Control Register.
    | XGETBV = 664
    /// Table Look-up Translation.
    | XLATB = 665
    /// Logical Exclusive OR.
    | XOR = 666
    /// Bitwise Logical XOR for Double-Precision Floating-Point Values.
    | XORPD = 667
    /// Bitwise Logical XOR for Single-Precision Floating-Point Values.
    | XORPS = 668
    /// Restore Processor Extended States.
    | XRSTOR = 669
    /// Save Processor Extended States.
    | XSAVE = 670
    /// Save Processor Extended States Optimized.
    | XSAVEOPT = 671
    /// Set Extended Control Register.
    | XSETBV = 672
    /// Test If In Transactional Execution.
    | XTEST = 673
    /// Invalid Opcode.
    | InvalOP = 674

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
type internal OprMode =
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
type internal OprSize =
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
    /// Register size = Doubledword, Pointer size = Word
    | DW = 0x240
    /// 32-bit, 48 bit, or 80-bit pointer, depending on operand-size attribute
    | P = 0x280
    /// 128-bit or 256-bit packed double-precision floating-point data
    | PD = 0x2c0
    /// Quadword MMX techonolgy register
    | PI = 0x300
    /// 128-bit or 256-bit packed single-precision floating-point data
    | PS = 0x340
    /// 128-bit or 256-bit packed single-precision floating-point data, pointer
    /// size : Quadword
    | PSQ = 0x380
    /// Quadword, regardless of operand-size attribute
    | Q = 0x3c0
    /// Quad-Quadword (256-bits), regardless of operand-size attribute
    | QQ = 0x400
    /// 6-byte or 10-byte pseudo-descriptor
    | S = 0x440
    /// Scalar element of a 128-bit double-precision floating data
    | SD = 0x480
    /// Scalar element of a 128-bit double-precision floating data, but the
    /// pointer size is quadword
    | SDQ = 0x4c0
    /// Scalar element of a 128-bit single-precision floating data
    | SS = 0x500
    /// Scalar element of a 128-bit single-precision floating data, but the
    /// pointer size is doubleword
    | SSD = 0x540
    /// Scalar element of a 128-bit single-precision floating data, but the
    /// pointer size is quadword
    | SSQ = 0x580
    /// Word/DWord/QWord depending on operand-size attribute
    | V = 0x5c0
    /// Word, regardless of operand-size attribute
    | W = 0x600
    /// dq or qq based on the operand-size attribute
    | X = 0x640
    /// 128-bit, 256-bit or 512-bit depending on operand-size attribute
    | XZ = 0x680
    /// Doubleword or quadword (in 64-bit mode), depending on operand-size
    /// attribute
    | Y = 0x6c0
    /// Word for 16-bit operand-size or DWord for 32 or 64-bit operand size
    | Z = 0x700

/// Defines attributes for registers to apply register conversion rules.
type internal RGrpAttr =
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
type internal OperandDesc =
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
type internal Scale =
    /// Times 1
    | X1 = 1
    /// Times 2
    | X2 = 2
    /// Times 4
    | X4 = 4
    /// Times 8
    | X8 = 8

/// Scaled index.
type internal ScaledIndex = Register * Scale

/// Jump target of a branch instruction.
type internal JumpTarget =
    | Absolute of Selector * Addr * OperandSize
    | Relative of Offset
and internal Selector = int16
and internal Offset = int64
and internal OperandSize = RegType

/// We define four different types of X86 operands:
/// register, memory, direct address, and immediate.
type internal Operand =
    | OprReg of Register
    | OprMem of Register option * ScaledIndex option * Disp option * OperandSize
    | OprDirAddr of JumpTarget
    | OprImm of int64
/// Displacement.
and Disp = int64

/// A set of operands in an X86 instruction.
type internal Operands =
    | NoOperand
    | OneOperand of Operand
    | TwoOperands of Operand * Operand
    | ThreeOperands of Operand * Operand * Operand
    | FourOperands of Operand * Operand * Operand * Operand

/// Specific conditions for determining the size of operands.
/// (See Appendix A.2.5 of Vol. 2D).
type internal SizeCond =
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
type internal VEXType =
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
type internal InsSize = {
    MemSize       : MemorySize
    RegSize       : RegType
    OperationSize : RegType
    SizeCond      : SizeCond
}
and internal MemorySize = {
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
type internal ZeroingOrMerging =
    | Zeroing
    | Merging

type internal EVEXPrefix = {
    Z   : ZeroingOrMerging
    AAA : uint8 (* Embedded opmask register specifier *)
}

/// Information about Intel vector extension.
type internal VEXInfo = {
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
type InsInfo = internal {
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
