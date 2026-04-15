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
/// Represents an Intel opcode.
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
  /// Add With Carry.
  | ADC = 4
  /// Unsigned Integer Addition of Two Operands With Carry Flag.
  | ADCX = 5
  /// Add.
  | ADD = 6
  /// Add Packed Double Precision Floating-Point Values.
  | ADDPD = 7
  /// Add Packed Single Precision Floating-Point Values.
  | ADDPS = 8
  /// Add Scalar Double Precision Floating-Point Values.
  | ADDSD = 9
  /// Add Scalar Single Precision Floating-Point Values.
  | ADDSS = 10
  /// Packed Double Precision Floating-Point Add/Subtract.
  | ADDSUBPD = 11
  /// Packed Single Precision Floating-Point Add/Subtract.
  | ADDSUBPS = 12
  /// Unsigned Integer Addition of Two Operands With Overflow Flag.
  | ADOX = 13
  /// Perform One Round of an AES Decryption Flow.
  | AESDEC = 14
  /// Perform Ten Rounds of AES Decryption Flow With Key Locker Using 128-Bit
  /// Key.
  | AESDEC128KL = 15
  /// Perform 14 Rounds of AES Decryption Flow With Key Locker Using 256-Bit
  /// Key.
  | AESDEC256KL = 16
  /// Perform Last Round of an AES Decryption Flow.
  | AESDECLAST = 17
  /// Perform Ten Rounds of AES Decryption Flow With Key Locker on 8 Blocks
  /// Using 128-Bit Key.
  | AESDECWIDE128KL = 18
  /// Perform 14 Rounds of AES Decryption Flow With Key Locker on 8 Blocks Using
  /// 256-Bit Key.
  | AESDECWIDE256KL = 19
  /// Perform One Round of an AES Encryption Flow.
  | AESENC = 20
  /// Perform Ten Rounds of AES Encryption Flow With Key Locker Using 128-Bit
  /// Key.
  | AESENC128KL = 21
  /// Perform 14 Rounds of AES Encryption Flow With Key Locker Using 256-Bit
  /// Key.
  | AESENC256KL = 22
  /// Perform Last Round of an AES Encryption Flow.
  | AESENCLAST = 23
  /// Perform Ten Rounds of AES Encryption Flow With Key Locker on 8 Blocks
  /// Using 128-Bit Key.
  | AESENCWIDE128KL = 24
  /// Perform 14 Rounds of AES Encryption Flow With Key Locker on 8 Blocks Using
  /// 256-Bit Key.
  | AESENCWIDE256KL = 25
  /// Perform the AES InvMixColumn Transformation.
  | AESIMC = 26
  /// AES Round Key Generation Assist.
  | AESKEYGENASSIST = 27
  /// Logical AND.
  | AND = 28
  /// Logical AND NOT.
  | ANDN = 29
  /// Bitwise Logical AND NOT of Packed Double Precision Floating-Point Values.
  | ANDNPD = 30
  /// Bitwise Logical AND NOT of Packed Single Precision Floating-Point Values.
  | ANDNPS = 31
  /// Bitwise Logical AND of Packed Double Precision Floating-Point Values.
  | ANDPD = 32
  /// Bitwise Logical AND of Packed Single Precision Floating-Point Values.
  | ANDPS = 33
  /// Adjust RPL Field of Segment Selector.
  | ARPL = 34
  /// Bit Field Extract.
  | BEXTR = 35
  /// Blend Packed Double Precision Floating-Point Values.
  | BLENDPD = 36
  /// Blend Packed Single Precision Floating-Point Values.
  | BLENDPS = 37
  /// Variable Blend Packed Double Precision Floating-Point Values.
  | BLENDVPD = 38
  /// Variable Blend Packed Single Precision Floating-Point Values.
  | BLENDVPS = 39
  /// Extract Lowest Set Isolated Bit.
  | BLSI = 40
  /// Get Mask Up to Lowest Set Bit.
  | BLSMSK = 41
  /// Reset Lowest Set Bit.
  | BLSR = 42
  /// Check Lower Bound.
  | BNDCL = 43
  /// Check Upper Bound.
  | BNDCN = 44
  /// Check Upper Bound.
  | BNDCU = 45
  /// Load Extended Bounds Using Address Translation.
  | BNDLDX = 46
  /// Make Bounds.
  | BNDMK = 47
  /// Move Bounds.
  | BNDMOV = 48
  /// Store Extended Bounds Using Address Translation.
  | BNDSTX = 49
  /// Check Array Index Against Bounds.
  | BOUND = 50
  /// Bit Scan Forward.
  | BSF = 51
  /// Bit Scan Reverse.
  | BSR = 52
  /// Byte Swap.
  | BSWAP = 53
  /// Bit Test.
  | BT = 54
  /// Bit Test and Complement.
  | BTC = 55
  /// Bit Test and Reset.
  | BTR = 56
  /// Bit Test and Set.
  | BTS = 57
  /// Zero High Bits Starting with Specified Bit Position.
  | BZHI = 58
  /// Call Procedure.
  | CALL = 59
  /// Convert Byte to Word/Convert Word to Doubleword/Convert Doubleword to
  /// Quadword.
  | CBW = 60
  /// Chinese national cryptographic algorithms.
  | CCS_ENCRYPT = 61
  /// Chinese national cryptographic algorithms.
  | CCS_HASH = 62
  /// Convert Word to Doubleword/Convert Doubleword to Quadword.
  | CDQ = 63
  /// Convert Byte to Word/Convert Word to Doubleword/Convert Doubleword to
  /// Quadword.
  | CDQE = 64
  /// Clear AC Flag in EFLAGS Register.
  | CLAC = 65
  /// Clear Carry Flag.
  | CLC = 66
  /// Clear Direction Flag.
  | CLD = 67
  /// Cache Line Demote.
  | CLDEMOTE = 68
  /// Flush Cache Line.
  | CLFLUSH = 69
  /// Flush Cache Line Optimized.
  | CLFLUSHOPT = 70
  /// Clear Interrupt Flag.
  | CLI = 71
  /// Clear Busy Flag in a Supervisor Shadow Stack Token.
  | CLRSSBSY = 72
  /// Clear Task-Switched Flag in CR0.
  | CLTS = 73
  /// Clear User Interrupt Flag.
  | CLUI = 74
  /// Cache Line Write Back.
  | CLWB = 75
  /// Complement Carry Flag.
  | CMC = 76
  /// Move if above (CF=0 and ZF=0).
  | CMOVA = 77
  /// Move if above or equal (CF=0).
  | CMOVAE = 78
  /// Move if below (CF=1).
  | CMOVB = 79
  /// Move if below or equal (CF=1 or ZF=1).
  | CMOVBE = 80
  /// Move if carry (CF=1).
  | CMOVC = 81
  /// Move if equal (ZF=1).
  | CMOVE = 82
  /// Move if greater (ZF=0 and SF=OF).
  | CMOVG = 83
  /// Move if greater or equal (SF=OF).
  | CMOVGE = 84
  /// ¡Á Move if less (SF OF).
  | CMOVL = 85
  /// ¡Á Move if less or equal (ZF=1 or SF OF).
  | CMOVLE = 86
  /// Move if not above (CF=1 or ZF=1).
  | CMOVNA = 87
  /// Move if not above or equal (CF=1).
  | CMOVNAE = 88
  /// Move if not below (CF=0).
  | CMOVNB = 89
  /// Move if not below or equal (CF=0 and ZF=0).
  | CMOVNBE = 90
  /// Move if not carry (CF=0).
  | CMOVNC = 91
  /// Move if not equal (ZF=0).
  | CMOVNE = 92
  /// ¡Á Move if not greater (ZF=1 or SF OF).
  | CMOVNG = 93
  /// ¡Á Move if not greater or equal (SF OF).
  | CMOVNGE = 94
  /// Move if not less (SF=OF).
  | CMOVNL = 95
  /// Move if not less or equal (ZF=0 and SF=OF).
  | CMOVNLE = 96
  /// Move if not overflow (OF=0).
  | CMOVNO = 97
  /// Move if not parity (PF=0).
  | CMOVNP = 98
  /// Move if not sign (SF=0).
  | CMOVNS = 99
  /// Move if not zero (ZF=0).
  | CMOVNZ = 100
  /// Move if overflow (OF=1).
  | CMOVO = 101
  /// Move if parity (PF=1).
  | CMOVP = 102
  /// Move if parity even (PF=1).
  | CMOVPE = 103
  /// Move if parity odd (PF=0).
  | CMOVPO = 104
  /// Move if sign (SF=1).
  | CMOVS = 105
  /// Move if zero (ZF=1).
  | CMOVZ = 106
  /// Compare Two Operands.
  | CMP = 107
  /// CMPBEXADD m32,r32,r32: Compare value in r32 (second operand) with value in
  /// m32. If below or equal (CF=1 or ZF=1), add value from r32 (third operand)
  /// to m32 and write new value in m32. The second operand is always updated
  /// with the original value from m32.
  /// CMPBEXADD m64,r64,r64: Compare value in r64 (second operand) with value in
  /// m64. If below or equal (CF=1 or ZF=1), add value from r64 (third operand)
  /// to m64 and write new value in m64. The second operand is always updated
  /// with the original value from m64.
  | CMPBEXADD = 108
  /// CMPBXADD m32,r32,r32: Compare value in r32 (second operand) with value in
  /// m32. If below (CF=1), add value from r32 (third operand) to m32 and write
  /// new value in m32. The second operand is always updated with the original
  /// value from m32.
  /// CMPBXADD m64,r64,r64: Compare value in r64 (second operand) with value in
  /// m64. If below (CF=1), add value from r64 (third operand) to m64 and write
  /// new value in m64. The second operand is always updated with the original
  /// value from m64.
  | CMPBXADD = 109
  /// CMPLEXADD m32,r32,r32: Compare value in r32 (second operand) with ¡Á value
  /// in m32. If less or equal (ZF=1 or SF OF), add value from r32 (third
  /// operand) to m32 and write new value in m32. The second operand is always
  /// updated with the original value from m32.
  /// CMPLEXADD m64,r64,r64: Compare value in r64 (second operand) with ¡Á value
  /// in m64. If less or equal (ZF=1 or SF OF), add value from r64 (third
  /// operand) to m64 and write new value in m64. The second operand is always
  /// updated with the original value from m64.
  | CMPLEXADD = 110
  /// CMPLXADD m32,r32,r32: Compare value in r32 (second operand) with ¡Á value
  /// in m32. If less (SF OF), add value from r32 (third operand) to m32 and
  /// write new value in m32. The second operand is always updated with the
  /// original value from m32.
  /// CMPLXADD m64,r64,r64: Compare value in r64 (second operand) with ¡Á value
  /// in m64. If less (SF OF), add value from r64 (third operand) to m64 and
  /// write new value in m64. The second operand is always updated with the
  /// original value from m64.
  | CMPLXADD = 111
  /// CMPNBEXADD m32,r32,r32: Compare value in r32 (second operand) with value
  /// in m32. If not below or equal (CF=0 and ZF=0), add value from r32 (third
  /// operand) to m32 and write new value in m32. The second operand is always
  /// updated with the original value from m32.
  /// CMPNBEXADD m64,r64,r64: Compare value in r64 (second operand) with value
  /// in m64. If not below or equal (CF=0 and ZF=0), add value from r64 (third
  /// operand) to m64 and write new value in m64. The second operand is always
  /// updated with the original value from m64.
  | CMPNBEXADD = 112
  /// CMPNBXADD m32,r32,r32: Compare value in r32 (second operand) with value in
  /// m32. If not below (CF=0), add value from r32 (third operand) to m32 and
  /// write new value in m32. The second operand is always updated with the
  /// original value from m32.
  /// CMPNBXADD m64,r64,r64: Compare value in r64 (second operand) with value in
  /// m64. If not below (CF=0), add value from r64 (third operand) to m64 and
  /// write new value in m64. The second operand is always updated with the
  /// original value from m64.
  | CMPNBXADD = 113
  /// CMPNLEXADD m32,r32,r32: Compare value in r32 (second operand) with value
  /// in m32. If not less or equal (ZF=0 and SF=OF), add value from r32 (third
  /// operand) to m32 and write new value in m32. The second operand is always
  /// updated with the original value from m32.
  /// CMPNLEXADD m64,r64,r64: Compare value in r64 (second operand) with value
  /// in m64. If not less or equal (ZF=0 and SF=OF), add value from r64 (third
  /// operand) to m64 and write new value in m64. The second operand is always
  /// updated with the original value from m64.
  | CMPNLEXADD = 114
  /// CMPNLXADD m32,r32,r32: Compare value in r32 (second operand) with value in
  /// m32. If not less (SF=OF), add value from r32 (third operand) to m32 and
  /// write new value in m32. The second operand is always updated with the
  /// original value from m32.
  /// CMPNLXADD m64,r64,r64: Compare value in r64 (second operand) with value in
  /// m64. If not less (SF=OF), add value from r64 (third operand) to m64 and
  /// write new value in m64. The second operand is always updated with the
  /// original value from m64.
  | CMPNLXADD = 115
  /// CMPNOXADD m32,r32,r32: Compare value in r32 (second operand) with value in
  /// m32. If not overflow (OF=0), add value from r32 (third operand) to m32 and
  /// write new value in m32. The second operand is always updated with the
  /// original value from m32.
  /// CMPNOXADD m64,r64,r64: Compare value in r64 (second operand) with value in
  /// m64. If not overflow (OF=0), add value from r64 (third operand) to m64 and
  /// write new value in m64. The second operand is always updated with the
  /// original value from m64.
  | CMPNOXADD = 116
  /// CMPNPXADD m32,r32,r32: Compare value in r32 (second operand) with value in
  /// m32. If not parity (PF=0), add value from r32 (third operand) to m32 and
  /// write new value in m32. The second operand is always updated with the
  /// original value from m32.
  /// CMPNPXADD m64,r64,r64: Compare value in r64 (second operand) with value in
  /// m64. If not parity (PF=0), add value from r64 (third operand) to m64 and
  /// write new value in m64. The second operand is always updated with the
  /// original value from m64.
  | CMPNPXADD = 117
  /// CMPNSXADD m32,r32,r32: Compare value in r32 (second operand) with value in
  /// m32. If not sign (SF=0), add value from r32 (third operand) to m32 and
  /// write new value in m32. The second operand is always updated with the
  /// original value from m32.
  /// CMPNSXADD m64,r64,r64: Compare value in r64 (second operand) with value in
  /// m64. If not sign (SF=0), add value from r64 (third operand) to m64 and
  /// write new value in m64. The second operand is always updated with the
  /// original value from m64.
  | CMPNSXADD = 118
  /// CMPNZXADD m32,r32,r32: Compare value in r32 (second operand) with value in
  /// m32. If not zero (ZF=0), add value from r32 (third operand) to m32 and
  /// write new value in m32. The second operand is always updated with the
  /// original value from m32.
  /// CMPNZXADD m64,r64,r64: Compare value in r64 (second operand) with value in
  /// m64. If not zero (ZF=0), add value from r64 (third operand) to m64 and
  /// write new value in m64. The second operand is always updated with the
  /// original value from m64.
  | CMPNZXADD = 119
  /// CMPOXADD m32,r32,r32: Compare value in r32 (second operand) with value in
  /// m32. If overflow (OF=1), add value from r32 (third operand) to m32 and
  /// write new value in m32. The second operand is always updated with the
  /// original value from m32.
  /// CMPOXADD m64,r64,r64: Compare value in r64 (second operand) with value in
  /// m64. If overflow (OF=1), add value from r64 (third operand) to m64 and
  /// write new value in m64. The second operand is always updated with the
  /// original value from m64.
  | CMPOXADD = 120
  /// Compare Packed Double Precision Floating-Point Values.
  | CMPPD = 121
  /// Compare Packed Single Precision Floating-Point Values.
  | CMPPS = 122
  /// CMPPXADD m32,r32,r32: Compare value in r32 (second operand) with value in
  /// m32. If parity (PF=1), add value from r32 (third operand) to m32 and write
  /// new value in m32. The second operand is always updated with the original
  /// value from m32.
  /// CMPPXADD m64,r64,r64: Compare value in r64 (second operand) with value in
  /// m64. If parity (PF=1), add value from r64 (third operand) to m64 and write
  /// new value in m64. The second operand is always updated with the original
  /// value from m64.
  | CMPPXADD = 123
  /// Compare String Operands.
  | CMPS = 124
  /// Compare String Operands.
  | CMPSB = 125
  /// Compare Scalar Double Precision Floating-Point Value.
  | CMPSD = 126
  /// Compare String Operands.
  | CMPSQ = 127
  /// Compare Scalar Single Precision Floating-Point Value.
  | CMPSS = 128
  /// Compare String Operands.
  | CMPSW = 129
  /// CMPSXADD m32,r32,r32: Compare value in r32 (second operand) with value in
  /// m32. If sign (SF=1), add value from r32 (third operand) to m32 and write
  /// new value in m32. The second operand is always updated with the original
  /// value from m32.
  /// CMPSXADD m64,r64,r64: Compare value in r64 (second operand) with value in
  /// m64. If sign (SF=1), add value from r64 (third operand) to m64 and write
  /// new value in m64. The second operand is always updated with the original
  /// value from m64.
  | CMPSXADD = 130
  /// Compare and Exchange.
  | CMPXCHG = 131
  /// Compare and Exchange Bytes.
  | CMPXCHG16B = 132
  /// Compare and Exchange Bytes.
  | CMPXCHG8B = 133
  /// CMPZXADD m32,r32,r32: Compare value in r32 (second operand) with value in
  /// m32. If zero (ZF=1), add value from r32 (third operand) to m32 and write
  /// new value in m32. The second operand is always updated with the original
  /// value from m32.
  /// CMPZXADD m64,r64,r64: Compare value in r64 (second operand) with value in
  /// m64. If zero (ZF=1), add value from r64 (third operand) to m64 and write
  /// new value in m64. The second operand is always updated with the original
  /// value from m64.
  | CMPZXADD = 134
  /// Compare Scalar Ordered Double Precision Floating-Point Values and Set
  /// EFLAGS.
  | COMISD = 135
  /// Compare Scalar Ordered Single Precision Floating-Point Values and Set
  /// EFLAGS.
  | COMISS = 136
  /// CPU Identification.
  | CPUID = 137
  /// Convert Word to Doubleword/Convert Doubleword to Quadword.
  | CQO = 138
  /// Accumulate CRC32 Value.
  | CRC32 = 139
  /// Convert Packed Doubleword Integers to Packed Double Precision
  /// Floating-Point Values.
  | CVTDQ2PD = 140
  /// Convert Packed Doubleword Integers to Packed Single Precision
  /// Floating-Point Values.
  | CVTDQ2PS = 141
  /// Convert Packed Double Precision Floating-Point Values to Packed Doubleword
  /// Integers.
  | CVTPD2DQ = 142
  /// Convert Packed Double Precision Floating-Point Values to Packed Dword
  /// Integers.
  | CVTPD2PI = 143
  /// Convert Packed Double Precision Floating-Point Values to Packed Single
  /// Precision Floating-Point Values.
  | CVTPD2PS = 144
  /// Convert Packed Dword Integers to Packed Double Precision Floating-Point
  /// Values.
  | CVTPI2PD = 145
  /// Convert Packed Dword Integers to Packed Single Precision Floating-Point
  /// Values.
  | CVTPI2PS = 146
  /// Convert Packed Single Precision Floating-Point Values to Packed Signed
  /// Doubleword Integer Values.
  | CVTPS2DQ = 147
  /// Convert Packed Single Precision Floating-Point Values to Packed Double
  /// Precision Floating-Point Values.
  | CVTPS2PD = 148
  /// Convert Packed Single Precision Floating-Point Values to Packed Dword
  /// Integers.
  | CVTPS2PI = 149
  /// Convert Scalar Double Precision Floating-Point Value to Signed Integer.
  | CVTSD2SI = 150
  /// Convert Scalar Double Precision Floating-Point Value to Scalar Single
  /// Precision Floating-Point Value.
  | CVTSD2SS = 151
  /// Convert Signed Integer to Scalar Double Precision Floating-Point Value.
  | CVTSI2SD = 152
  /// Convert Signed Integer to Scalar Single Precision Floating-Point Value.
  | CVTSI2SS = 153
  /// Convert Scalar Single Precision Floating-Point Value to Scalar Double
  /// Precision Floating-Point Value.
  | CVTSS2SD = 154
  /// Convert Scalar Single Precision Floating-Point Value to Signed Integer.
  | CVTSS2SI = 155
  /// Convert with Truncation Packed Double Precision Floating-Point Values to
  /// Packed Doubleword Integers.
  | CVTTPD2DQ = 156
  /// Convert With Truncation Packed Double Precision Floating-Point Values to
  /// Packed Dword Integers.
  | CVTTPD2PI = 157
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Signed Doubleword Integer Values.
  | CVTTPS2DQ = 158
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Dword Integers.
  | CVTTPS2PI = 159
  /// Convert With Truncation Scalar Double Precision Floating-Point Value to
  /// Signed Integer.
  | CVTTSD2SI = 160
  /// Convert With Truncation Scalar Single Precision Floating-Point Value to
  /// Signed Integer.
  | CVTTSS2SI = 161
  /// Convert Word to Doubleword/Convert Doubleword to Quadword.
  | CWD = 162
  /// Convert Byte to Word/Convert Word to Doubleword/Convert Doubleword to
  /// Quadword.
  | CWDE = 163
  /// Decimal Adjust AL After Addition.
  | DAA = 164
  /// Decimal Adjust AL After Subtraction.
  | DAS = 165
  /// Decrement by 1.
  | DEC = 166
  /// Unsigned Divide.
  | DIV = 167
  /// Divide Packed Double Precision Floating-Point Values.
  | DIVPD = 168
  /// Divide Packed Single Precision Floating-Point Values.
  | DIVPS = 169
  /// Divide Scalar Double Precision Floating-Point Value.
  | DIVSD = 170
  /// Divide Scalar Single Precision Floating-Point Values.
  | DIVSS = 171
  /// Dot Product of Packed Double Precision Floating-Point Values.
  | DPPD = 172
  /// Dot Product of Packed Single Precision Floating-Point Values.
  | DPPS = 173
  /// Empty MMX Technology State.
  | EMMS = 174
  /// Encode 128-Bit Key With Key Locker.
  | ENCODEKEY128 = 175
  /// Encode 256-Bit Key With Key Locker.
  | ENCODEKEY256 = 176
  /// Terminate an Indirect Branch in 32-bit and Compatibility Mode.
  | ENDBR32 = 177
  /// Terminate an Indirect Branch in 64-bit Mode.
  | ENDBR64 = 178
  /// Enqueue Command.
  | ENQCMD = 179
  /// Enqueue Command Supervisor.
  | ENQCMDS = 180
  /// Make Stack Frame for Procedure Parameters.
  | ENTER = 181
  /// Extract Packed Floating-Point Values.
  | EXTRACTPS = 182
  /// Extract Field from Register.
  | EXTRQ = 183
  /// Compute 2x-1.
  | F2XM1 = 184
  /// Absolute Value.
  | FABS = 185
  /// Add.
  | FADD = 186
  /// Add.
  | FADDP = 187
  /// Load Binary Coded Decimal.
  | FBLD = 188
  /// Store BCD Integer and Pop.
  | FBSTP = 189
  /// Change Sign.
  | FCHS = 190
  /// Clear Exceptions.
  | FCLEX = 191
  /// Move if below (CF=1).
  | FCMOVB = 192
  /// Move if below or equal (CF=1 or ZF=1).
  | FCMOVBE = 193
  /// Move if equal (ZF=1).
  | FCMOVE = 194
  /// Move if not below (CF=0).
  | FCMOVNB = 195
  /// Move if not below or equal (CF=0 and ZF=0).
  | FCMOVNBE = 196
  /// Move if not equal (ZF=0).
  | FCMOVNE = 197
  /// Move if not unordered (PF=0).
  | FCMOVNU = 198
  /// Move if unordered (PF=1).
  | FCMOVU = 199
  /// Compare Floating-Point Values.
  | FCOM = 200
  /// Compare Floating-Point Values and Set EFLAGS.
  | FCOMI = 201
  /// Compare Floating-Point Values and Set EFLAGS.
  | FCOMIP = 202
  /// Compare Floating-Point Values.
  | FCOMP = 203
  /// Compare Floating-Point Values.
  | FCOMPP = 204
  /// Cosine.
  | FCOS = 205
  /// Decrement Stack-Top Pointer.
  | FDECSTP = 206
  /// Divide.
  | FDIV = 207
  /// Divide.
  | FDIVP = 208
  /// Reverse Divide.
  | FDIVR = 209
  /// Reverse Divide.
  | FDIVRP = 210
  /// Free Floating-Point Register.
  | FFREE = 211
  /// Performs FFREE ST(i) and pop stack.
  | FFREEP = 212
  /// Add.
  | FIADD = 213
  /// Compare Integer.
  | FICOM = 214
  /// Compare Integer.
  | FICOMP = 215
  /// Divide.
  | FIDIV = 216
  /// Reverse Divide.
  | FIDIVR = 217
  /// Load Integer.
  | FILD = 218
  /// Multiply.
  | FIMUL = 219
  /// Increment Stack-Top Pointer.
  | FINCSTP = 220
  /// Initialize Floating-Point Unit.
  | FINIT = 221
  /// Store Integer.
  | FIST = 222
  /// Store Integer.
  | FISTP = 223
  /// Store Integer With Truncation.
  | FISTTP = 224
  /// Subtract.
  | FISUB = 225
  /// Reverse Subtract.
  | FISUBR = 226
  /// Load Floating-Point Value.
  | FLD = 227
  /// Load Constant.
  | FLD1 = 228
  /// Load x87 FPU Control Word.
  | FLDCW = 229
  /// Load x87 FPU Environment.
  | FLDENV = 230
  /// Load Constant.
  | FLDL2E = 231
  /// Load Constant.
  | FLDL2T = 232
  /// Load Constant.
  | FLDLG2 = 233
  /// Load Constant.
  | FLDLN2 = 234
  /// Load Constant.
  | FLDPI = 235
  /// Load Constant.
  | FLDZ = 236
  /// Multiply.
  | FMUL = 237
  /// Multiply.
  | FMULP = 238
  /// Clear Exceptions.
  | FNCLEX = 239
  /// Initialize Floating-Point Unit.
  | FNINIT = 240
  /// No Operation.
  | FNOP = 241
  /// Store x87 FPU State.
  | FNSAVE = 242
  /// Store x87 FPU Control Word.
  | FNSTCW = 243
  /// Store x87 FPU Environment.
  | FNSTENV = 244
  /// Store x87 FPU Status Word.
  | FNSTSW = 245
  /// Partial Arctangent.
  | FPATAN = 246
  /// Partial Remainder.
  | FPREM = 247
  /// Partial Remainder.
  | FPREM1 = 248
  /// Partial Tangent.
  | FPTAN = 249
  /// Round to Integer.
  | FRNDINT = 250
  /// Restore x87 FPU State.
  | FRSTOR = 251
  /// Store x87 FPU State.
  | FSAVE = 252
  /// Scale.
  | FSCALE = 253
  /// Sine.
  | FSIN = 254
  /// Sine and Cosine.
  | FSINCOS = 255
  /// Square Root.
  | FSQRT = 256
  /// Store Floating-Point Value.
  | FST = 257
  /// Store x87 FPU Control Word.
  | FSTCW = 258
  /// Store x87 FPU Environment.
  | FSTENV = 259
  /// Store Floating-Point Value.
  | FSTP = 260
  /// Store x87 FPU Status Word.
  | FSTSW = 261
  /// Subtract.
  | FSUB = 262
  /// Subtract.
  | FSUBP = 263
  /// Reverse Subtract.
  | FSUBR = 264
  /// Reverse Subtract.
  | FSUBRP = 265
  /// TEST.
  | FTST = 266
  /// Unordered Compare Floating-Point Values.
  | FUCOM = 267
  /// Compare Floating-Point Values and Set EFLAGS.
  | FUCOMI = 268
  /// Compare Floating-Point Values and Set EFLAGS.
  | FUCOMIP = 269
  /// Unordered Compare Floating-Point Values.
  | FUCOMP = 270
  /// Unordered Compare Floating-Point Values.
  | FUCOMPP = 271
  /// Wait.
  | FWAIT = 272
  /// Examine Floating-Point.
  | FXAM = 273
  /// Exchange Register Contents.
  | FXCH = 274
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR = 275
  /// Restore the x87 FPU, MMX, XMM, and MXCSR register state from m512byte.
  | FXRSTOR64 = 276
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE = 277
  /// Save the x87 FPU, MMX, XMM, and MXCSR register state to m512byte.
  | FXSAVE64 = 278
  /// Extract Exponent and Significand.
  | FXTRACT = 279
  /// Compute y * log2x.
  | FYL2X = 280
  /// Compute y * log2(x +1).
  | FYL2XP1 = 281
  /// GETSEC leaf functions are selected by the value in EAX on input.
  | GETSEC = 282
  /// Galois Field Affine Transformation Inverse.
  | GF2P8AFFINEINVQB = 283
  /// Galois Field Affine Transformation.
  | GF2P8AFFINEQB = 284
  /// Galois Field Multiply Bytes.
  | GF2P8MULB = 285
  /// Packed Double Precision Floating-Point Horizontal Add.
  | HADDPD = 286
  /// Packed Single Precision Floating-Point Horizontal Add.
  | HADDPS = 287
  /// Halt.
  | HLT = 288
  /// History Reset.
  | HRESET = 289
  /// Packed Double Precision Floating-Point Horizontal Subtract.
  | HSUBPD = 290
  /// Packed Single Precision Floating-Point Horizontal Subtract.
  | HSUBPS = 291
  /// Signed Divide.
  | IDIV = 292
  /// Signed Multiply.
  | IMUL = 293
  /// Input From Port.
  | IN = 294
  /// Increment by 1.
  | INC = 295
  /// Increment Shadow Stack Pointer.
  | INCSSPD = 296
  /// Increment Shadow Stack Pointer.
  | INCSSPQ = 297
  /// Input from Port to String.
  | INS = 298
  /// Input from Port to String.
  | INSB = 299
  /// Input from Port to String.
  | INSD = 300
  /// Insert Scalar Single Precision Floating-Point Value.
  | INSERTPS = 301
  /// Inserts Field from a source Register to a destination Register.
  | INSERTQ = 302
  /// Input from Port to String.
  | INSW = 303
  /// Single-Step Interrupt 3.
  | INT = 304
  /// Call to Interrupt Procedure.
  | INT1 = 305
  /// Call to Interrupt Procedure.
  | INT3 = 306
  /// Call to Interrupt Procedure.
  | INTO = 307
  /// Invalidate Internal Caches.
  | INVD = 308
  /// Invalidate TLB Entries.
  | INVLPG = 309
  /// Invalidate Process-Context Identifier.
  | INVPCID = 310
  /// Interrupt Return.
  | IRET = 311
  /// Interrupt Return.
  | IRETD = 312
  /// Interrupt Return.
  | IRETQ = 313
  /// Interrupt return (16-bit operand size).
  | IRETW = 314
  /// JA rel8: Jump short if above (CF=0 and ZF=0).
  /// JA rel16: Jump near if above (CF=0 and ZF=0). Not supported in 64-bit
  /// mode.
  /// JA rel32: Jump near if above (CF=0 and ZF=0).
  | JA = 315
  /// JAE rel8: Jump short if above or equal (CF=0).
  /// JAE rel16: Jump near if above or equal (CF=0). Not supported in 64-bit
  /// mode.
  /// JAE rel32: Jump near if above or equal (CF=0).
  | JAE = 316
  /// JB rel8: Jump short if below (CF=1).
  /// JB rel16: Jump near if below (CF=1). Not supported in 64-bit mode.
  /// JB rel32: Jump near if below (CF=1).
  | JB = 317
  /// JBE rel8: Jump short if below or equal (CF=1 or ZF=1).
  /// JBE rel16: Jump near if below or equal (CF=1 or ZF=1). Not supported in
  /// 64-bit mode.
  /// JBE rel32: Jump near if below or equal (CF=1 or ZF=1).
  | JBE = 318
  /// JC rel8: Jump short if carry (CF=1).
  /// JC rel16: Jump near if carry (CF=1). Not supported in 64-bit mode.
  /// JC rel32: Jump near if carry (CF=1).
  | JC = 319
  /// Jump on CX/ECX Zero Address-size prefix differentiates JCXZ and JECXZ.
  | JCXZ = 320
  /// JE rel8: Jump short if equal (ZF=1).
  /// JE rel16: Jump near if equal (ZF=1). Not supported in 64-bit mode.
  /// JE rel32: Jump near if equal (ZF=1).
  | JE = 321
  /// Jump on CX/ECX Zero Address-size prefix differentiates JCXZ and JECXZ.
  | JECXZ = 322
  /// JG rel8: Jump short if greater (ZF=0 and SF=OF).
  /// JG rel16: Jump near if greater (ZF=0 and SF=OF). Not supported in 64-bit
  /// mode.
  /// JG rel32: Jump near if greater (ZF=0 and SF=OF).
  | JG = 323
  /// JGE rel8: Jump short if greater or equal (SF=OF).
  /// JGE rel16: Jump near if greater or equal (SF=OF). Not supported in 64-bit
  /// mode.
  /// JGE rel32: Jump near if greater or equal (SF=OF).
  | JGE = 324
  /// JL rel8: ¡Á Jump short if less (SF OF).
  /// JL rel16: ¡Á Jump near if less (SF OF). Not supported in 64-bit mode.
  /// JL rel32: ¡Á Jump near if less (SF OF).
  | JL = 325
  /// JLE rel8: ¡Á Jump short if less or equal (ZF=1 or SF OF).
  /// JLE rel16: ¡Á Jump near if less or equal (ZF=1 or SF OF). Not supported in
  /// 64-bit mode.
  /// JLE rel32: ¡Á Jump near if less or equal (ZF=1 or SF OF).
  | JLE = 326
  /// Jump.
  | JMP = 327
  /// JNA rel8: Jump short if not above (CF=1 or ZF=1).
  /// JNA rel16: Jump near if not above (CF=1 or ZF=1). Not supported in 64-bit
  /// mode.
  /// JNA rel32: Jump near if not above (CF=1 or ZF=1).
  | JNA = 328
  /// JNAE rel8: Jump short if not above or equal (CF=1).
  /// JNAE rel16: Jump near if not above or equal (CF=1). Not supported in
  /// 64-bit mode.
  /// JNAE rel32: Jump near if not above or equal (CF=1).
  | JNAE = 329
  /// JNB rel8: Jump short if not below (CF=0).
  /// JNB rel16: Jump near if not below (CF=0). Not supported in 64-bit mode.
  /// JNB rel32: Jump near if not below (CF=0).
  | JNB = 330
  /// JNBE rel8: Jump short if not below or equal (CF=0 and ZF=0).
  /// JNBE rel16: Jump near if not below or equal (CF=0 and ZF=0). Not supported
  /// in 64-bit mode.
  /// JNBE rel32: Jump near if not below or equal (CF=0 and ZF=0).
  | JNBE = 331
  /// JNC rel8: Jump short if not carry (CF=0).
  /// JNC rel16: Jump near if not carry (CF=0). Not supported in 64-bit mode.
  /// JNC rel32: Jump near if not carry (CF=0).
  | JNC = 332
  /// JNE rel8: Jump short if not equal (ZF=0).
  /// JNE rel16: Jump near if not equal (ZF=0). Not supported in 64-bit mode.
  /// JNE rel32: Jump near if not equal (ZF=0).
  | JNE = 333
  /// JNG rel8: ¡Á Jump short if not greater (ZF=1 or SF OF).
  /// JNG rel16: ¡Á Jump near if not greater (ZF=1 or SF OF). Not supported in
  /// 64-bit mode.
  /// JNG rel32: ¡Á Jump near if not greater (ZF=1 or SF OF).
  | JNG = 334
  /// JNGE rel8: ¡Á Jump short if not greater or equal (SF OF).
  /// JNGE rel16: ¡Á Jump near if not greater or equal (SF OF). Not supported in
  /// 64-bit mode.
  /// JNGE rel32: ¡Á Jump near if not greater or equal (SF OF).
  | JNGE = 335
  /// JNL rel8: Jump short if not less (SF=OF).
  /// JNL rel16: Jump near if not less (SF=OF). Not supported in 64-bit mode.
  /// JNL rel32: Jump near if not less (SF=OF).
  | JNL = 336
  /// JNLE rel8: Jump short if not less or equal (ZF=0 and SF=OF).
  /// JNLE rel16: Jump near if not less or equal (ZF=0 and SF=OF). Not supported
  /// in 64-bit mode.
  /// JNLE rel32: Jump near if not less or equal (ZF=0 and SF=OF).
  | JNLE = 337
  /// JNO rel8: Jump short if not overflow (OF=0).
  /// JNO rel16: Jump near if not overflow (OF=0). Not supported in 64-bit mode.
  /// JNO rel32: Jump near if not overflow (OF=0).
  | JNO = 338
  /// JNP rel8: Jump short if not parity (PF=0).
  /// JNP rel16: Jump near if not parity (PF=0). Not supported in 64-bit mode.
  /// JNP rel32: Jump near if not parity (PF=0).
  | JNP = 339
  /// JNS rel8: Jump short if not sign (SF=0).
  /// JNS rel16: Jump near if not sign (SF=0). Not supported in 64-bit mode.
  /// JNS rel32: Jump near if not sign (SF=0).
  | JNS = 340
  /// JNZ rel8: Jump short if not zero (ZF=0).
  /// JNZ rel16: Jump near if not zero (ZF=0). Not supported in 64-bit mode.
  /// JNZ rel32: Jump near if not zero (ZF=0).
  | JNZ = 341
  /// JO rel8: Jump short if overflow (OF=1).
  /// JO rel16: Jump near if overflow (OF=1). Not supported in 64-bit mode.
  /// JO rel32: Jump near if overflow (OF=1).
  | JO = 342
  /// JP rel8: Jump short if parity (PF=1).
  /// JP rel16: Jump near if parity (PF=1). Not supported in 64-bit mode.
  /// JP rel32: Jump near if parity (PF=1).
  | JP = 343
  /// JPE rel8: Jump short if parity even (PF=1).
  /// JPE rel16: Jump near if parity even (PF=1). Not supported in 64-bit mode.
  /// JPE rel32: Jump near if parity even (PF=1).
  | JPE = 344
  /// JPO rel8: Jump short if parity odd (PF=0).
  /// JPO rel16: Jump near if parity odd (PF=0). Not supported in 64-bit mode.
  /// JPO rel32: Jump near if parity odd (PF=0).
  | JPO = 345
  /// Jump short if RCX register is 0.
  | JRCXZ = 346
  /// JS rel8: Jump short if sign (SF=1).
  /// JS rel16: Jump near if sign (SF=1). Not supported in 64-bit mode.
  /// JS rel32: Jump near if sign (SF=1).
  | JS = 347
  /// JZ rel8: Jump short if zero (ZF = 1).
  /// JZ rel16: Jump near if 0 (ZF=1). Not supported in 64-bit mode.
  /// JZ rel32: Jump near if 0 (ZF=1).
  | JZ = 348
  /// ADD Two Masks.
  | KADDB = 349
  /// ADD Two Masks.
  | KADDD = 350
  /// ADD Two Masks.
  | KADDQ = 351
  /// ADD Two Masks.
  | KADDW = 352
  /// Bitwise Logical AND Masks.
  | KANDB = 353
  /// Bitwise Logical AND Masks.
  | KANDD = 354
  /// Bitwise Logical AND NOT Masks.
  | KANDNB = 355
  /// Bitwise Logical AND NOT Masks.
  | KANDND = 356
  /// Bitwise Logical AND NOT Masks.
  | KANDNQ = 357
  /// Bitwise Logical AND NOT Masks.
  | KANDNW = 358
  /// Bitwise Logical AND Masks.
  | KANDQ = 359
  /// Bitwise Logical AND Masks.
  | KANDW = 360
  /// Move From and to Mask Registers.
  | KMOVB = 361
  /// Move From and to Mask Registers.
  | KMOVD = 362
  /// Move From and to Mask Registers.
  | KMOVQ = 363
  /// Move From and to Mask Registers.
  | KMOVW = 364
  /// NOT Mask Register.
  | KNOTB = 365
  /// NOT Mask Register.
  | KNOTD = 366
  /// NOT Mask Register.
  | KNOTQ = 367
  /// NOT Mask Register.
  | KNOTW = 368
  /// Bitwise Logical OR Masks.
  | KORB = 369
  /// Bitwise Logical OR Masks.
  | KORD = 370
  /// Bitwise Logical OR Masks.
  | KORQ = 371
  /// OR Masks and Set Flags.
  | KORTESTB = 372
  /// OR Masks and Set Flags.
  | KORTESTD = 373
  /// OR Masks and Set Flags.
  | KORTESTQ = 374
  /// OR Masks and Set Flags.
  | KORTESTW = 375
  /// Bitwise Logical OR Masks.
  | KORW = 376
  /// Shift Left Mask Registers.
  | KSHIFTLB = 377
  /// Shift Left Mask Registers.
  | KSHIFTLD = 378
  /// Shift Left Mask Registers.
  | KSHIFTLQ = 379
  /// Shift Left Mask Registers.
  | KSHIFTLW = 380
  /// Shift Right Mask Registers.
  | KSHIFTRB = 381
  /// Shift Right Mask Registers.
  | KSHIFTRD = 382
  /// Shift Right Mask Registers.
  | KSHIFTRQ = 383
  /// Shift Right Mask Registers.
  | KSHIFTRW = 384
  /// Packed Bit Test Masks and Set Flags.
  | KTESTB = 385
  /// Packed Bit Test Masks and Set Flags.
  | KTESTD = 386
  /// Packed Bit Test Masks and Set Flags.
  | KTESTQ = 387
  /// Packed Bit Test Masks and Set Flags.
  | KTESTW = 388
  /// Unpack for Mask Registers.
  | KUNPCKBW = 389
  /// Unpack for Mask Registers.
  | KUNPCKDQ = 390
  /// Unpack for Mask Registers.
  | KUNPCKWD = 391
  /// Bitwise Logical XNOR Masks.
  | KXNORB = 392
  /// Bitwise Logical XNOR Masks.
  | KXNORD = 393
  /// Bitwise Logical XNOR Masks.
  | KXNORQ = 394
  /// Bitwise Logical XNOR Masks.
  | KXNORW = 395
  /// Bitwise Logical XOR Masks.
  | KXORB = 396
  /// Bitwise Logical XOR Masks.
  | KXORD = 397
  /// Bitwise Logical XOR Masks.
  | KXORQ = 398
  /// Bitwise Logical XOR Masks.
  | KXORW = 399
  /// Load Status Flags Into AH Register.
  | LAHF = 400
  /// Load Access Rights.
  | LAR = 401
  /// Load Unaligned Integer 128 Bits.
  | LDDQU = 402
  /// Load MXCSR Register.
  | LDMXCSR = 403
  /// Load Far Pointer.
  | LDS = 404
  /// Load Tile Configuration.
  | LDTILECFG = 405
  /// Load Effective Address.
  | LEA = 406
  /// High Level Procedure Exit.
  | LEAVE = 407
  /// Load Far Pointer.
  | LES = 408
  /// Load Fence.
  | LFENCE = 409
  /// Load Far Pointer.
  | LFS = 410
  /// Load Global/Interrupt Descriptor Table Register.
  | LGDT = 411
  /// Load Far Pointer.
  | LGS = 412
  /// Load Global/Interrupt Descriptor Table Register.
  | LIDT = 413
  /// Load Local Descriptor Table Register.
  | LLDT = 414
  /// Load Machine Status Word.
  | LMSW = 415
  /// Load Internal Wrapping Key With Key Locker.
  | LOADIWKEY = 416
  /// Assert LOCK# Signal Prefix.
  | LOCK = 417
  /// Load String.
  | LODS = 418
  /// Load String.
  | LODSB = 419
  /// Load String.
  | LODSD = 420
  /// Load String.
  | LODSQ = 421
  /// Load String.
  | LODSW = 422
  /// Loop According to ECX Counter.
  | LOOP = 423
  /// Loop Count while Zero/Equal.
  | LOOPE = 424
  /// Loop Count while not Zero/Equal.
  | LOOPNE = 425
  /// Load Segment Limit.
  | LSL = 426
  /// Load Far Pointer.
  | LSS = 427
  /// Load Task Register.
  | LTR = 428
  /// Count the Number of Leading Zero Bits.
  | LZCNT = 429
  /// Store Selected Bytes of Double Quadword.
  | MASKMOVDQU = 430
  /// Store Selected Bytes of Quadword.
  | MASKMOVQ = 431
  /// Maximum of Packed Double Precision Floating-Point Values.
  | MAXPD = 432
  /// Maximum of Packed Single Precision Floating-Point Values.
  | MAXPS = 433
  /// Return Maximum Scalar Double Precision Floating-Point Value.
  | MAXSD = 434
  /// Return Maximum Scalar Single Precision Floating-Point Value.
  | MAXSS = 435
  /// Memory Fence.
  | MFENCE = 436
  /// Minimum of Packed Double Precision Floating-Point Values.
  | MINPD = 437
  /// Minimum of Packed Single Precision Floating-Point Values.
  | MINPS = 438
  /// Return Minimum Scalar Double Precision Floating-Point Value.
  | MINSD = 439
  /// Return Minimum Scalar Single Precision Floating-Point Value.
  | MINSS = 440
  /// Set Up Monitor Address.
  | MONITOR = 441
  /// Montgomery multiplier (PMM).
  | MONTMUL = 442
  /// Montgomery multiplier (PMM).
  | MONTMUL2 = 443
  /// Move to/from Control Registers.
  | MOV = 444
  /// Move Aligned Packed Double Precision Floating-Point Values.
  | MOVAPD = 445
  /// Move Aligned Packed Single Precision Floating-Point Values.
  | MOVAPS = 446
  /// Move Data After Swapping Bytes.
  | MOVBE = 447
  /// Move Doubleword/Move Quadword.
  | MOVD = 448
  /// Replicate Double Precision Floating-Point Values.
  | MOVDDUP = 449
  /// Move 64 Bytes as Direct Store.
  | MOVDIR64B = 450
  /// Move Doubleword as Direct Store.
  | MOVDIRI = 451
  /// Move Quadword from XMM to MMX Technology Register.
  | MOVDQ2Q = 452
  /// Move Aligned Packed Integer Values.
  | MOVDQA = 453
  /// Move Unaligned Packed Integer Values.
  | MOVDQU = 454
  /// Move Packed Single Precision Floating-Point Values High to Low.
  | MOVHLPS = 455
  /// Move High Packed Double Precision Floating-Point Value.
  | MOVHPD = 456
  /// Move High Packed Single Precision Floating-Point Values.
  | MOVHPS = 457
  /// Move Packed Single Precision Floating-Point Values Low to High.
  | MOVLHPS = 458
  /// Move Low Packed Double Precision Floating-Point Value.
  | MOVLPD = 459
  /// Move Low Packed Single Precision Floating-Point Values.
  | MOVLPS = 460
  /// Extract Packed Double Precision Floating-Point Sign Mask.
  | MOVMSKPD = 461
  /// Extract Packed Single Precision Floating-Point Sign Mask.
  | MOVMSKPS = 462
  /// Store Packed Integers Using Non-Temporal Hint.
  | MOVNTDQ = 463
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQA = 464
  /// Store Doubleword Using Non-Temporal Hint.
  | MOVNTI = 465
  /// Store Packed Double Precision Floating-Point Values Using Non-Temporal
  /// Hint.
  | MOVNTPD = 466
  /// Store Packed Single Precision Floating-Point Values Using Non-Temporal
  /// Hint.
  | MOVNTPS = 467
  /// Store of Quadword Using Non-Temporal Hint.
  | MOVNTQ = 468
  /// Move Doubleword/Move Quadword.
  | MOVQ = 469
  /// Move Quadword from MMX Technology to XMM Register.
  | MOVQ2DQ = 470
  /// Move Data From String to String.
  | MOVS = 471
  /// Move Data From String to String.
  | MOVSB = 472
  /// Move or Merge Scalar Double Precision Floating-Point Value.
  | MOVSD = 473
  /// Replicate Single Precision Floating-Point Values.
  | MOVSHDUP = 474
  /// Replicate Single Precision Floating-Point Values.
  | MOVSLDUP = 475
  /// Move Data From String to String.
  | MOVSQ = 476
  /// Move or Merge Scalar Single Precision Floating-Point Value.
  | MOVSS = 477
  /// Move Data From String to String.
  | MOVSW = 478
  /// Move With Sign-Extension.
  | MOVSX = 479
  /// Move With Sign-Extension.
  | MOVSXD = 480
  /// Move Unaligned Packed Double Precision Floating-Point Values.
  | MOVUPD = 481
  /// Move Unaligned Packed Single Precision Floating-Point Values.
  | MOVUPS = 482
  /// Move With Zero-Extend.
  | MOVZX = 483
  /// Compute Multiple Packed Sums of Absolute Difference.
  | MPSADBW = 484
  /// Unsigned Multiply.
  | MUL = 485
  /// Multiply Packed Double Precision Floating-Point Values.
  | MULPD = 486
  /// Multiply Packed Single Precision Floating-Point Values.
  | MULPS = 487
  /// Multiply Scalar Double Precision Floating-Point Value.
  | MULSD = 488
  /// Multiply Scalar Single Precision Floating-Point Values.
  | MULSS = 489
  /// Unsigned Multiply Without Affecting Flags.
  | MULX = 490
  /// Monitor Wait.
  | MWAIT = 491
  /// Two's Complement Negation.
  | NEG = 492
  /// No Operation.
  | NOP = 493
  /// One's Complement Negation.
  | NOT = 494
  /// Logical Inclusive OR.
  | OR = 495
  /// Bitwise Logical OR of Packed Double Precision Floating-Point Values.
  | ORPD = 496
  /// Bitwise Logical OR of Packed Single Precision Floating-Point Values.
  | ORPS = 497
  /// Output to Port.
  | OUT = 498
  /// Output String to Port.
  | OUTS = 499
  /// Output String to Port.
  | OUTSB = 500
  /// Output String to Port.
  | OUTSD = 501
  /// Output String to Port.
  | OUTSW = 502
  /// Packed Absolute Value.
  | PABSB = 503
  /// Packed Absolute Value.
  | PABSD = 504
  /// Packed Absolute Value.
  | PABSW = 505
  /// Pack With Signed Saturation.
  | PACKSSDW = 506
  /// Pack With Signed Saturation.
  | PACKSSWB = 507
  /// Pack With Unsigned Saturation.
  | PACKUSDW = 508
  /// Pack With Unsigned Saturation.
  | PACKUSWB = 509
  /// Add Packed Integers.
  | PADDB = 510
  /// Add Packed Integers.
  | PADDD = 511
  /// Add Packed Integers.
  | PADDQ = 512
  /// Add Packed Signed Integers with Signed Saturation.
  | PADDSB = 513
  /// Add Packed Signed Integers with Signed Saturation.
  | PADDSW = 514
  /// Add Packed Unsigned Integers With Unsigned Saturation.
  | PADDUSB = 515
  /// Add Packed Unsigned Integers With Unsigned Saturation.
  | PADDUSW = 516
  /// Add Packed Integers.
  | PADDW = 517
  /// Packed Align Right.
  | PALIGNR = 518
  /// Logical AND.
  | PAND = 519
  /// Logical AND NOT.
  | PANDN = 520
  /// Spin Loop Hint.
  | PAUSE = 521
  /// Average Packed Integers.
  | PAVGB = 522
  /// Average Packed Integers.
  | PAVGW = 523
  /// Variable Blend Packed Bytes.
  | PBLENDVB = 524
  /// Blend Packed Words.
  | PBLENDW = 525
  /// Carry-Less Multiplication Quadword.
  | PCLMULQDQ = 526
  /// Compare Packed Data for Equal.
  | PCMPEQB = 527
  /// Compare Packed Data for Equal.
  | PCMPEQD = 528
  /// Compare Packed Qword Data for Equal.
  | PCMPEQQ = 529
  /// Compare Packed Data for Equal.
  | PCMPEQW = 530
  /// Packed Compare Explicit Length Strings, Return Index.
  | PCMPESTRI = 531
  /// Packed Compare Explicit Length Strings, Return Mask.
  | PCMPESTRM = 532
  /// Compare Packed Signed Integers for Greater Than.
  | PCMPGTB = 533
  /// Compare Packed Signed Integers for Greater Than.
  | PCMPGTD = 534
  /// Compare Packed Data for Greater Than.
  | PCMPGTQ = 535
  /// Compare Packed Signed Integers for Greater Than.
  | PCMPGTW = 536
  /// Packed Compare Implicit Length Strings, Return Index.
  | PCMPISTRI = 537
  /// Packed Compare Implicit Length Strings, Return Mask.
  | PCMPISTRM = 538
  /// Platform Configuration.
  | PCONFIG = 539
  /// Parallel Bits Deposit.
  | PDEP = 540
  /// Parallel Bits Extract.
  | PEXT = 541
  /// Extract Byte/Dword/Qword.
  | PEXTRB = 542
  /// Extract Byte/Dword/Qword.
  | PEXTRD = 543
  /// Extract Byte/Dword/Qword.
  | PEXTRQ = 544
  /// Extract Word.
  | PEXTRW = 545
  /// Packed Horizontal Add.
  | PHADDD = 546
  /// Packed Horizontal Add and Saturate.
  | PHADDSW = 547
  /// Packed Horizontal Add.
  | PHADDW = 548
  /// Packed Horizontal Word Minimum.
  | PHMINPOSUW = 549
  /// Packed Horizontal Subtract.
  | PHSUBD = 550
  /// Packed Horizontal Subtract and Saturate.
  | PHSUBSW = 551
  /// Packed Horizontal Subtract.
  | PHSUBW = 552
  /// Insert Byte/Dword/Qword.
  | PINSRB = 553
  /// Insert Byte/Dword/Qword.
  | PINSRD = 554
  /// Insert Byte/Dword/Qword.
  | PINSRQ = 555
  /// Insert Word.
  | PINSRW = 556
  /// Multiply and Add Packed Signed and Unsigned Bytes.
  | PMADDUBSW = 557
  /// Multiply and Add Packed Integers.
  | PMADDWD = 558
  /// Maximum of Packed Signed Integers.
  | PMAXSB = 559
  /// Maximum of Packed Signed Integers.
  | PMAXSD = 560
  /// Maximum of Packed Signed Integers.
  | PMAXSW = 561
  /// Maximum of Packed Unsigned Integers.
  | PMAXUB = 562
  /// Maximum of Packed Unsigned Integers.
  | PMAXUD = 563
  /// Maximum of Packed Unsigned Integers.
  | PMAXUW = 564
  /// Minimum of Packed Signed Integers.
  | PMINSB = 565
  /// Minimum of Packed Signed Integers.
  | PMINSD = 566
  /// Minimum of Packed Signed Integers.
  | PMINSW = 567
  /// Minimum of Packed Unsigned Integers.
  | PMINUB = 568
  /// Minimum of Packed Unsigned Integers.
  | PMINUD = 569
  /// Minimum of Packed Unsigned Integers.
  | PMINUW = 570
  /// Move Byte Mask.
  | PMOVMSKB = 571
  /// Packed Move Sign Extend - Byte to Dword.
  | PMOVSXBD = 572
  /// Packed Move Sign Extend - Byte to Qword.
  | PMOVSXBQ = 573
  /// Packed Move Sign Extend - Byte to Word.
  | PMOVSXBW = 574
  /// Packed Move Sign Extend - Dword to Qword.
  | PMOVSXDQ = 575
  /// Packed Move Sign Extend - Word to Dword.
  | PMOVSXWD = 576
  /// Packed Move Sign Extend - Word to Qword.
  | PMOVSXWQ = 577
  /// Packed Move Zero Extend - Byte to Dword.
  | PMOVZXBD = 578
  /// Packed Move Zero Extend - Byte to Qword.
  | PMOVZXBQ = 579
  /// Packed Move Zero Extend - Byte to Word.
  | PMOVZXBW = 580
  /// Packed Move Zero Extend - Dword to Qword.
  | PMOVZXDQ = 581
  /// Packed Move Zero Extend - Word to Dword.
  | PMOVZXWD = 582
  /// Packed Move Zero Extend - Word to Qword.
  | PMOVZXWQ = 583
  /// Multiply Packed Doubleword Integers.
  | PMULDQ = 584
  /// Packed Multiply High With Round and Scale.
  | PMULHRSW = 585
  /// Multiply Packed Unsigned Integers and Store High Result.
  | PMULHUW = 586
  /// Multiply Packed Signed Integers and Store High Result.
  | PMULHW = 587
  /// Multiply Packed Integers and Store Low Result.
  | PMULLD = 588
  /// Multiply Packed Signed Integers and Store Low Result.
  | PMULLW = 589
  /// Multiply Packed Unsigned Doubleword Integers.
  | PMULUDQ = 590
  /// Pop a Value From the Stack.
  | POP = 591
  /// Pop All General-Purpose Registers.
  | POPA = 592
  /// Pop All General-Purpose Registers.
  | POPAD = 593
  /// Return the Count of Number of Bits Set to 1.
  | POPCNT = 594
  /// Pop Stack Into EFLAGS Register.
  | POPF = 595
  /// Pop Stack Into EFLAGS Register.
  | POPFD = 596
  /// Pop Stack Into EFLAGS Register.
  | POPFQ = 597
  /// Bitwise Logical OR.
  | POR = 598
  /// Move code from relative address closer to the processor using IT0 hint.
  | PREFETCHIT0 = 599
  /// Move code from relative address closer to the processor using IT1 hint.
  | PREFETCHIT1 = 600
  /// Prefetch Non-Temporal to All Cache Levels 0000 1111:0001 1000:modA 000
  /// mem.
  | PREFETCHNTA = 601
  /// Prefetch Temporal to All Cache Levels 0000 1111:0001 1000:modA 001 mem.
  | PREFETCHT0 = 602
  /// Prefetch Temporal to First Level Cache 0000 1111:0001 1000:modA 010 mem.
  | PREFETCHT1 = 603
  /// Prefetch Temporal to Second Level Cache 0000 1111:0001 1000:modA 011 mem.
  | PREFETCHT2 = 604
  /// Prefetch Data Into Caches in Anticipation of a Write.
  | PREFETCHW = 605
  /// Prefetch Vector Data Into Caches With Intent to Write and T1 Hint.
  | PREFETCHWT1 = 606
  /// Compute Sum of Absolute Differences.
  | PSADBW = 607
  /// Packed Shuffle Bytes.
  | PSHUFB = 608
  /// Shuffle Packed Doublewords.
  | PSHUFD = 609
  /// Shuffle Packed High Words.
  | PSHUFHW = 610
  /// Shuffle Packed Low Words.
  | PSHUFLW = 611
  /// Shuffle Packed Words.
  | PSHUFW = 612
  /// Packed SIGN.
  | PSIGNB = 613
  /// Packed SIGN.
  | PSIGND = 614
  /// Packed SIGN.
  | PSIGNW = 615
  /// Shift Packed Data Left Logical.
  | PSLLD = 616
  /// Shift Double Quadword Left Logical.
  | PSLLDQ = 617
  /// Shift Packed Data Left Logical.
  | PSLLQ = 618
  /// Shift Packed Data Left Logical.
  | PSLLW = 619
  /// Shift Packed Data Right Arithmetic.
  | PSRAD = 620
  /// Shift Packed Data Right Arithmetic.
  | PSRAW = 621
  /// Shift Packed Data Right Logical.
  | PSRLD = 622
  /// Shift Double Quadword Right Logical.
  | PSRLDQ = 623
  /// Shift Packed Data Right Logical.
  | PSRLQ = 624
  /// Shift Packed Data Right Logical.
  | PSRLW = 625
  /// Subtract Packed Integers.
  | PSUBB = 626
  /// Subtract Packed Integers.
  | PSUBD = 627
  /// Subtract Packed Quadword Integers.
  | PSUBQ = 628
  /// Subtract Packed Signed Integers With Signed Saturation.
  | PSUBSB = 629
  /// Subtract Packed Signed Integers With Signed Saturation.
  | PSUBSW = 630
  /// Subtract Packed Unsigned Integers With Unsigned Saturation.
  | PSUBUSB = 631
  /// Subtract Packed Unsigned Integers With Unsigned Saturation.
  | PSUBUSW = 632
  /// Subtract Packed Integers.
  | PSUBW = 633
  /// Logical Compare.
  | PTEST = 634
  /// Write Data to a Processor Trace Packet.
  | PTWRITE = 635
  /// Unpack High Data.
  | PUNPCKHBW = 636
  /// Unpack High Data.
  | PUNPCKHDQ = 637
  /// Unpack High Data.
  | PUNPCKHQDQ = 638
  /// Unpack High Data.
  | PUNPCKHWD = 639
  /// Unpack Low Data.
  | PUNPCKLBW = 640
  /// Unpack Low Data.
  | PUNPCKLDQ = 641
  /// Unpack Low Data.
  | PUNPCKLQDQ = 642
  /// Unpack Low Data.
  | PUNPCKLWD = 643
  /// Push Word, Doubleword, or Quadword Onto the Stack.
  | PUSH = 644
  /// Push All General-Purpose Registers.
  | PUSHA = 645
  /// Push All General-Purpose Registers.
  | PUSHAD = 646
  /// Push EFLAGS Register Onto the Stack.
  | PUSHF = 647
  /// Push EFLAGS Register Onto the Stack.
  | PUSHFD = 648
  /// Push EFLAGS Register Onto the Stack.
  | PUSHFQ = 649
  /// Logical Exclusive OR.
  | PXOR = 650
  /// Rotate.
  | RCL = 651
  /// Compute Reciprocals of Packed Single Precision Floating-Point Values.
  | RCPPS = 652
  /// Compute Reciprocal of Scalar Single Precision Floating-Point Values.
  | RCPSS = 653
  /// Rotate.
  | RCR = 654
  /// Read FS/GS Segment Base.
  | RDFSBASE = 655
  /// Read FS/GS Segment Base.
  | RDGSBASE = 656
  /// Read From Model Specific Register.
  | RDMSR = 657
  /// Read List of Model Specific Registers.
  | RDMSRLIST = 658
  /// Read Processor ID.
  | RDPID = 659
  /// Read Protection Key Rights for User Pages.
  | RDPKRU = 660
  /// Read Performance-Monitoring Counters.
  | RDPMC = 661
  /// Read Random Number.
  | RDRAND = 662
  /// Read Random SEED.
  | RDSEED = 663
  /// Read Shadow Stack Pointer.
  | RDSSPD = 664
  /// Read Shadow Stack Pointer.
  | RDSSPQ = 665
  /// Read Time-Stamp Counter.
  | RDTSC = 666
  /// Read Time-Stamp Counter and Processor ID.
  | RDTSCP = 667
  /// Return From Procedure.
  | RET = 668
  /// Rotate.
  | ROL = 669
  /// Rotate.
  | ROR = 670
  /// Rotate Right Logical Without Affecting Flags.
  | RORX = 671
  /// Round Packed Double Precision Floating-Point Values.
  | ROUNDPD = 672
  /// Round Packed Single Precision Floating-Point Values.
  | ROUNDPS = 673
  /// Round Scalar Double Precision Floating-Point Values.
  | ROUNDSD = 674
  /// Round Scalar Single Precision Floating-Point Values.
  | ROUNDSS = 675
  /// Resume From System Management Mode.
  | RSM = 676
  /// Compute Reciprocals of Square Roots of Packed Single Precision
  /// Floating-Point Values.
  | RSQRTPS = 677
  /// Compute Reciprocal of Square Root of Scalar Single Precision
  /// Floating-Point Value.
  | RSQRTSS = 678
  /// Restore Saved Shadow Stack Pointer.
  | RSTORSSP = 679
  /// Store AH Into Flags.
  | SAHF = 680
  /// Shift.
  | SAL = 681
  /// Shift.
  | SAR = 682
  /// Shift Without Affecting Flags.
  | SARX = 683
  /// Save Previous Shadow Stack Pointer.
  | SAVEPREVSSP = 684
  /// Integer Subtraction With Borrow.
  | SBB = 685
  /// Scan String.
  | SCAS = 686
  /// Scan String.
  | SCASB = 687
  /// Scan String.
  | SCASD = 688
  /// Scan String.
  | SCASQ = 689
  /// Scan String.
  | SCASW = 690
  /// Send User Interprocessor Interrupt.
  | SENDUIPI = 691
  /// Serialize Instruction Execution.
  | SERIALIZE = 692
  /// Set byte if above (CF=0 and ZF=0).
  | SETA = 693
  /// Set byte if above or equal (CF=0).
  | SETAE = 694
  /// Set byte if below (CF=1).
  | SETB = 695
  /// Set byte if below or equal (CF=1 or ZF=1).
  | SETBE = 696
  /// Set byte if carry (CF=1).
  | SETC = 697
  /// Set byte if equal (ZF=1).
  | SETE = 698
  /// Set byte if greater (ZF=0 and SF=OF).
  | SETG = 699
  /// Set byte if greater or equal (SF=OF).
  | SETGE = 700
  /// ¡Á Set byte if less (SF OF).
  | SETL = 701
  /// ¡Á Set byte if less or equal (ZF=1 or SF OF).
  | SETLE = 702
  /// Set byte if not above (CF=1 or ZF=1).
  | SETNA = 703
  /// Set byte if not above or equal (CF=1).
  | SETNAE = 704
  /// Set byte if not below (CF=0).
  | SETNB = 705
  /// Set byte if not below or equal (CF=0 and ZF=0).
  | SETNBE = 706
  /// Set byte if not carry (CF=0).
  | SETNC = 707
  /// Set byte if not equal (ZF=0).
  | SETNE = 708
  /// ¡Á Set byte if not greater (ZF=1 or SF OF).
  | SETNG = 709
  /// ¡Á Set byte if not greater or equal (SF OF).
  | SETNGE = 710
  /// Set byte if not less (SF=OF).
  | SETNL = 711
  /// Set byte if not less or equal (ZF=0 and SF=OF).
  | SETNLE = 712
  /// Set byte if not overflow (OF=0).
  | SETNO = 713
  /// Set byte if not parity (PF=0).
  | SETNP = 714
  /// Set byte if not sign (SF=0).
  | SETNS = 715
  /// Set byte if not zero (ZF=0).
  | SETNZ = 716
  /// Set byte if overflow (OF=1).
  | SETO = 717
  /// Set byte if parity (PF=1).
  | SETP = 718
  /// Set byte if parity even (PF=1).
  | SETPE = 719
  /// Set byte if parity odd (PF=0).
  | SETPO = 720
  /// Set byte if sign (SF=1).
  | SETS = 721
  /// Mark Shadow Stack Busy.
  | SETSSBSY = 722
  /// Set byte if zero (ZF=1).
  | SETZ = 723
  /// Store Fence.
  | SFENCE = 724
  /// Store Global Descriptor Table Register.
  | SGDT = 725
  /// Perform an Intermediate Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG1 = 726
  /// Perform a Final Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG2 = 727
  /// Calculate SHA1 State Variable E After Four Rounds.
  | SHA1NEXTE = 728
  /// Perform Four Rounds of SHA1 Operation.
  | SHA1RNDS4 = 729
  /// Perform an Intermediate Calculation for the Next Four SHA256 Message
  /// Dwords.
  | SHA256MSG1 = 730
  /// Perform a Final Calculation for the Next Four SHA256 Message Dwords.
  | SHA256MSG2 = 731
  /// Perform Two Rounds of SHA256 Operation.
  | SHA256RNDS2 = 732
  /// Shift.
  | SHL = 733
  /// Double Precision Shift Left.
  | SHLD = 734
  /// Shift Without Affecting Flags.
  | SHLX = 735
  /// Shift.
  | SHR = 736
  /// Double Precision Shift Right.
  | SHRD = 737
  /// Shift Without Affecting Flags.
  | SHRX = 738
  /// Packed Interleave Shuffle of Pairs of Double Precision Floating-Point
  /// Values.
  | SHUFPD = 739
  /// Packed Interleave Shuffle of Quadruplets of Single Precision
  /// Floating-Point Values.
  | SHUFPS = 740
  /// Store Interrupt Descriptor Table Register.
  | SIDT = 741
  /// Store Local Descriptor Table Register.
  | SLDT = 742
  /// Chinese national cryptographic algorithms.
  | SM2 = 743
  /// Store Machine Status Word.
  | SMSW = 744
  /// Square Root of Double Precision Floating-Point Values.
  | SQRTPD = 745
  /// Square Root of Single Precision Floating-Point Values.
  | SQRTPS = 746
  /// Compute Square Root of Scalar Double Precision Floating-Point Value.
  | SQRTSD = 747
  /// Compute Square Root of Scalar Single Precision Value.
  | SQRTSS = 748
  /// Set AC Flag in EFLAGS Register.
  | STAC = 749
  /// Set Carry Flag.
  | STC = 750
  /// Set Direction Flag.
  | STD = 751
  /// Set Interrupt Flag.
  | STI = 752
  /// Store MXCSR Register State.
  | STMXCSR = 753
  /// Store String.
  | STOS = 754
  /// Store String.
  | STOSB = 755
  /// Store String.
  | STOSD = 756
  /// Store String.
  | STOSQ = 757
  /// Store String.
  | STOSW = 758
  /// Store Task Register.
  | STR = 759
  /// Store Tile Configuration.
  | STTILECFG = 760
  /// Set User Interrupt Flag.
  | STUI = 761
  /// Subtract.
  | SUB = 762
  /// Subtract Packed Double Precision Floating-Point Values.
  | SUBPD = 763
  /// Subtract Packed Single Precision Floating-Point Values.
  | SUBPS = 764
  /// Subtract Scalar Double Precision Floating-Point Value.
  | SUBSD = 765
  /// Subtract Scalar Single Precision Floating-Point Value.
  | SUBSS = 766
  /// Swap GS Base Register.
  | SWAPGS = 767
  /// Fast System Call.
  | SYSCALL = 768
  /// Fast System Call.
  | SYSENTER = 769
  /// Fast Return from Fast System Call.
  | SYSEXIT = 770
  /// Return From Fast System Call.
  | SYSRET = 771
  /// Dot Product of BF16 Tiles Accumulated into Packed Single Precision Tile.
  | TDPBF16PS = 772
  /// Dot Product of Signed/Unsigned Bytes with Dword Accumulation.
  | TDPBSSD = 773
  /// Dot Product of Signed/Unsigned Bytes with Dword Accumulation.
  | TDPBSUD = 774
  /// Dot Product of Signed/Unsigned Bytes with Dword Accumulation.
  | TDPBUSD = 775
  /// Dot Product of Signed/Unsigned Bytes with Dword Accumulation.
  | TDPBUUD = 776
  /// Dot Product of FP16 Tiles Accumulated into Packed Single Precision Tile.
  | TDPFP16PS = 777
  /// Logical Compare.
  | TEST = 778
  /// Determine User Interrupt Flag.
  | TESTUI = 779
  /// Load Tile.
  | TILELOADD = 780
  /// Load Tile.
  | TILELOADDT1 = 781
  /// Release Tile.
  | TILERELEASE = 782
  /// Store Tile.
  | TILESTORED = 783
  /// Zero Tile.
  | TILEZERO = 784
  /// Timed PAUSE.
  | TPAUSE = 785
  /// Count the Number of Trailing Zero Bits.
  | TZCNT = 786
  /// Unordered Compare Scalar Double Precision Floating-Point Values and Set
  /// EFLAGS.
  | UCOMISD = 787
  /// Unordered Compare Scalar Single Precision Floating-Point Values and Set
  /// EFLAGS.
  | UCOMISS = 788
  /// Undefined instruction.
  | UD0 = 789
  /// Undefined instruction.
  | UD1 = 790
  /// Undefined instruction.
  | UD2 = 791
  /// Undefined Instruction.
  | UDB = 792
  /// User-Interrupt Return.
  | UIRET = 793
  /// User Level Set Up Monitor Address.
  | UMONITOR = 794
  /// User Level Monitor Wait.
  | UMWAIT = 795
  /// Unpack and Interleave High Packed Double Precision Floating-Point Values.
  | UNPCKHPD = 796
  /// Unpack and Interleave High Packed Single Precision Floating-Point Values.
  | UNPCKHPS = 797
  /// Unpack and Interleave Low Packed Double Precision Floating-Point Values.
  | UNPCKLPD = 798
  /// Unpack and Interleave Low Packed Single Precision Floating-Point Values.
  | UNPCKLPS = 799
  /// Packed Single Precision Floating-Point Fused Multiply-Add (4-Iterations).
  | V4FMADDPS = 800
  /// Scalar Single Precision Floating-Point Fused Multiply-Add (4-Iterations).
  | V4FMADDSS = 801
  /// Packed Single Precision Floating-Point Fused Multiply-Add (4-Iterations).
  | V4FNMADDPS = 802
  /// Scalar Single Precision Floating-Point Fused Multiply-Add (4-Iterations).
  | V4FNMADDSS = 803
  /// Add Packed Double Precision Floating-Point Values.
  | VADDPD = 804
  /// Add Packed FP16 Values.
  | VADDPH = 805
  /// Add Packed Single Precision Floating-Point Values.
  | VADDPS = 806
  /// Add Scalar Double Precision Floating-Point Values.
  | VADDSD = 807
  /// Add Scalar FP16 Values.
  | VADDSH = 808
  /// Add Scalar Single Precision Floating-Point Values.
  | VADDSS = 809
  /// Packed Double Precision Floating-Point Add/Subtract.
  | VADDSUBPD = 810
  /// Packed Single Precision Floating-Point Add/Subtract.
  | VADDSUBPS = 811
  /// Perform One Round of an AES Decryption Flow.
  | VAESDEC = 812
  /// Perform Last Round of an AES Decryption Flow.
  | VAESDECLAST = 813
  /// Perform One Round of an AES Encryption Flow.
  | VAESENC = 814
  /// Perform Last Round of an AES Encryption Flow.
  | VAESENCLAST = 815
  /// Perform the AES InvMixColumn Transformation.
  | VAESIMC = 816
  /// AES Round Key Generation Assist.
  | VAESKEYGENASSIST = 817
  /// Align Doubleword/Quadword Vectors.
  | VALIGND = 818
  /// Align Doubleword/Quadword Vectors.
  | VALIGNQ = 819
  /// Bitwise Logical AND NOT of Packed Double Precision Floating-Point Values.
  | VANDNPD = 820
  /// Bitwise Logical AND NOT of Packed Single Precision Floating-Point Values.
  | VANDNPS = 821
  /// Bitwise Logical AND of Packed Double Precision Floating-Point Values.
  | VANDPD = 822
  /// Bitwise Logical AND of Packed Single Precision Floating-Point Values.
  | VANDPS = 823
  /// Load BF16 Element and Convert to FP32 Element With Broadcast.
  | VBCSTNEBF162PS = 824
  /// Load FP16 Element and Convert to FP32 Element with Broadcast.
  | VBCSTNESH2PS = 825
  /// Blend Float64/Float32 Vectors Using an OpMask Control.
  | VBLENDMPD = 826
  /// Blend Float64/Float32 Vectors Using an OpMask Control.
  | VBLENDMPS = 827
  /// Blend Packed Double Precision Floating-Point Values.
  | VBLENDPD = 828
  /// Blend Packed Single Precision Floating-Point Values.
  | VBLENDPS = 829
  /// Variable Blend Packed Double Precision Floating-Point Values.
  | VBLENDVPD = 830
  /// Variable Blend Packed Single Precision Floating-Point Values.
  | VBLENDVPS = 831
  /// Broadcast 128 bits of floating-point data in mem to low and high 128-bits
  /// in ymm1.
  | VBROADCASTF128 = 832
  /// VBROADCASTF32X2 ymm1{k1}{z},xmm2/m64: Broadcast two single precision
  /// floating-point elements in xmm2/m64 to locations in ymm1 using writemask
  /// k1.
  /// VBROADCASTF32X2 zmm1{k1}{z},xmm2/m64: Broadcast two single precision
  /// floating-point elements in xmm2/m64 to locations in zmm1 using writemask
  /// k1.
  | VBROADCASTF32X2 = 833
  /// VBROADCASTF32X4 ymm1{k1}{z},m128: Broadcast 128 bits of 4 single precision
  /// floating-point data in mem to locations in ymm1 using writemask k1.
  /// VBROADCASTF32X4 zmm1{k1}{z},m128: Broadcast 128 bits of 4 single precision
  /// floating-point data in mem to locations in zmm1 using writemask k1.
  | VBROADCASTF32X4 = 834
  /// Broadcast 256 bits of 8 single precision floating-point data in mem to
  /// locations in zmm1 using writemask k1.
  | VBROADCASTF32X8 = 835
  /// VBROADCASTF64X2 ymm1{k1}{z},m128: Broadcast 128 bits of 2 double precision
  /// floating-point data in mem to locations in ymm1 using writemask k1.
  /// VBROADCASTF64X2 zmm1{k1}{z},m128: Broadcast 128 bits of 2 double precision
  /// floating-point data in mem to locations in zmm1 using writemask k1.
  | VBROADCASTF64X2 = 836
  /// Broadcast 256 bits of 4 double precision floating-point data in mem to
  /// locations in zmm1 using writemask k1.
  | VBROADCASTF64X4 = 837
  /// Broadcast 128 bits of integer data in mem to low and high 128-bits in
  /// ymm1.
  | VBROADCASTI128 = 838
  /// VBROADCASTI32x2 xmm1{k1}{z},xmm2/m64: Broadcast two dword elements in
  /// source operand to locations in xmm1 subject to writemask k1.
  /// VBROADCASTI32x2 ymm1{k1}{z},xmm2/m64: Broadcast two dword elements in
  /// source operand to locations in ymm1 subject to writemask k1.
  /// VBROADCASTI32x2 zmm1{k1}{z},xmm2/m64: Broadcast two dword elements in
  /// source operand to locations in zmm1 subject to writemask k1.
  | VBROADCASTI32X2 = 839
  /// VBROADCASTI32X4 ymm1{k1}{z},m128: Broadcast 128 bits of 4 doubleword
  /// integer data in mem to locations in ymm1 using writemask k1.
  /// VBROADCASTI32X4 zmm1{k1}{z},m128: Broadcast 128 bits of 4 doubleword
  /// integer data in mem to locations in zmm1 using writemask k1.
  | VBROADCASTI32X4 = 840
  /// Broadcast 256 bits of 8 doubleword integer data in mem to locations in
  /// zmm1 using writemask k1.
  | VBROADCASTI32X8 = 841
  /// VBROADCASTI64X2 ymm1{k1}{z},m128: Broadcast 128 bits of 2 quadword integer
  /// data in mem to locations in ymm1 using writemask k1.
  /// VBROADCASTI64X2 zmm1{k1}{z},m128: Broadcast 128 bits of 2 quadword integer
  /// data in mem to locations in zmm1 using writemask k1.
  | VBROADCASTI64X2 = 842
  /// Broadcast 256 bits of 4 quadword integer data in mem to locations in zmm1
  /// using writemask k1.
  | VBROADCASTI64X4 = 843
  /// VBROADCASTSD ymm1,m64: Broadcast double precision floating-point element
  /// in mem to four locations in ymm1.
  /// VBROADCASTSD ymm1,xmm2: Broadcast low double precision floating-point
  /// element in the source operand to four locations in ymm1.
  /// VBROADCASTSD ymm1{k1}{z},xmm2/m64: Broadcast low double precision
  /// floating-point element in xmm2/m64 to four locations in ymm1 using
  /// writemask k1.
  /// VBROADCASTSD zmm1{k1}{z},xmm2/m64: Broadcast low double precision
  /// floating-point element in xmm2/m64 to eight locations in zmm1 using
  /// writemask k1.
  | VBROADCASTSD = 844
  /// VBROADCASTSS xmm1,m32: Broadcast single precision floating-point element
  /// in mem to four locations in xmm1.
  /// VBROADCASTSS ymm1,m32: Broadcast single precision floating-point element
  /// in mem to eight locations in ymm1.
  /// VBROADCASTSS xmm1,xmm2: Broadcast the low single precision floating-point
  /// element in the source operand to four locations in xmm1.
  /// VBROADCASTSS ymm1,xmm2: Broadcast low single precision floating-point
  /// element in the source operand to eight locations in ymm1.
  /// VBROADCASTSS xmm1{k1}{z},xmm2/m32: Broadcast low single precision
  /// floating-point element in xmm2/m32 to all locations in xmm1 using
  /// writemask k1.
  /// VBROADCASTSS ymm1{k1}{z},xmm2/m32: Broadcast low single precision
  /// floating-point element in xmm2/m32 to all locations in ymm1 using
  /// writemask k1.
  /// VBROADCASTSS zmm1{k1}{z},xmm2/m32: Broadcast low single precision
  /// floating-point element in xmm2/m32 to all locations in zmm1 using
  /// writemask k1.
  | VBROADCASTSS = 845
  /// Compare Packed Double Precision Floating-Point Values.
  | VCMPPD = 846
  /// Compare Packed FP16 Values.
  | VCMPPH = 847
  /// Compare Packed Single Precision Floating-Point Values.
  | VCMPPS = 848
  /// Compare Scalar Double Precision Floating-Point Value.
  | VCMPSD = 849
  /// Compare Scalar FP16 Values.
  | VCMPSH = 850
  /// Compare Scalar Single Precision Floating-Point Value.
  | VCMPSS = 851
  /// Compare Scalar Ordered Double Precision Floating-Point Values and Set
  /// EFLAGS.
  | VCOMISD = 852
  /// Compare Scalar Ordered FP16 Values and Set EFLAGS.
  | VCOMISH = 853
  /// Compare Scalar Ordered Single Precision Floating-Point Values and Set
  /// EFLAGS.
  | VCOMISS = 854
  /// Store Sparse Packed Double Precision Floating-Point Values Into Dense
  /// Memory.
  | VCOMPRESSPD = 855
  /// Store Sparse Packed Single Precision Floating-Point Values Into Dense
  /// Memory.
  | VCOMPRESSPS = 856
  /// Convert Packed Doubleword Integers to Packed Double Precision
  /// Floating-Point Values.
  | VCVTDQ2PD = 857
  /// Convert Packed Signed Doubleword Integers to Packed FP16 Values.
  | VCVTDQ2PH = 858
  /// Convert Packed Doubleword Integers to Packed Single Precision
  /// Floating-Point Values.
  | VCVTDQ2PS = 859
  /// Convert Two Packed Single Data to One Packed BF16 Data.
  | VCVTNE2PS2BF16 = 860
  /// Convert Even Elements of Packed BF16 Values to FP32 Values.
  | VCVTNEEBF162PS = 861
  /// Convert Even Elements of Packed FP16 Values to FP32 Values.
  | VCVTNEEPH2PS = 862
  /// Convert Odd Elements of Packed BF16 Values to FP32 Values.
  | VCVTNEOBF162PS = 863
  /// Convert Odd Elements of Packed FP16 Values to FP32 Values.
  | VCVTNEOPH2PS = 864
  /// Convert Packed Single Data to Packed BF16 Data.
  | VCVTNEPS2BF16 = 865
  /// Convert Packed Double Precision Floating-Point Values to Packed Doubleword
  /// Integers.
  | VCVTPD2DQ = 866
  /// Convert Packed Double Precision FP Values to Packed FP16 Values.
  | VCVTPD2PH = 867
  /// Convert Packed Double Precision Floating-Point Values to Packed Single
  /// Precision Floating-Point Values.
  | VCVTPD2PS = 868
  /// Convert Packed Double Precision Floating-Point Values to Packed Quadword
  /// Integers.
  | VCVTPD2QQ = 869
  /// Convert Packed Double Precision Floating-Point Values to Packed Unsigned
  /// Doubleword Integers.
  | VCVTPD2UDQ = 870
  /// Convert Packed Double Precision Floating-Point Values to Packed Unsigned
  /// Quadword Integers.
  | VCVTPD2UQQ = 871
  /// Convert Packed FP16 Values to Signed Doubleword Integers.
  | VCVTPH2DQ = 872
  /// Convert Packed FP16 Values to FP64 Values.
  | VCVTPH2PD = 873
  /// Convert Packed FP16 Values to Single Precision Floating-Point Values.
  | VCVTPH2PS = 874
  /// Convert Packed FP16 Values to Single Precision Floating-Point Values.
  | VCVTPH2PSX = 875
  /// Convert Packed FP16 Values to Signed Quadword Integer Values.
  | VCVTPH2QQ = 876
  /// Convert Packed FP16 Values to Unsigned Doubleword Integers.
  | VCVTPH2UDQ = 877
  /// Convert Packed FP16 Values to Unsigned Quadword Integers.
  | VCVTPH2UQQ = 878
  /// Convert Packed FP16 Values to Unsigned Word Integers.
  | VCVTPH2UW = 879
  /// Convert Packed FP16 Values to Signed Word Integers.
  | VCVTPH2W = 880
  /// Convert Packed Single Precision Floating-Point Values to Packed Signed
  /// Doubleword Integer Values.
  | VCVTPS2DQ = 881
  /// Convert Packed Single Precision Floating-Point Values to Packed Double
  /// Precision Floating-Point Values.
  | VCVTPS2PD = 882
  /// Convert Single Precision FP Value to 16-bit FP Value.
  | VCVTPS2PH = 883
  /// Convert Packed Single Precision Floating-Point Values to Packed FP16
  /// Values.
  | VCVTPS2PHX = 884
  /// Convert Packed Single Precision Floating-Point Values to Packed Signed
  /// Quadword Integer Values.
  | VCVTPS2QQ = 885
  /// Convert Packed Single Precision Floating-Point Values to Packed Unsigned
  /// Doubleword Integer Values.
  | VCVTPS2UDQ = 886
  /// Convert Packed Single Precision Floating-Point Values to Packed Unsigned
  /// Quadword Integer Values.
  | VCVTPS2UQQ = 887
  /// Convert Packed Quadword Integers to Packed Double Precision Floating-Point
  /// Values.
  | VCVTQQ2PD = 888
  /// Convert Packed Signed Quadword Integers to Packed FP16 Values.
  | VCVTQQ2PH = 889
  /// Convert Packed Quadword Integers to Packed Single Precision Floating-Point
  /// Values.
  | VCVTQQ2PS = 890
  /// Convert Low FP64 Value to an FP16 Value.
  | VCVTSD2SH = 891
  /// Convert Scalar Double Precision Floating-Point Value to Signed Integer.
  | VCVTSD2SI = 892
  /// Convert Scalar Double Precision Floating-Point Value to Scalar Single
  /// Precision Floating-Point Value.
  | VCVTSD2SS = 893
  /// Convert Scalar Double Precision Floating-Point Value to Unsigned Integer.
  | VCVTSD2USI = 894
  /// Convert Low FP16 Value to an FP64 Value.
  | VCVTSH2SD = 895
  /// Convert Low FP16 Value to Signed Integer.
  | VCVTSH2SI = 896
  /// Convert Low FP16 Value to FP32 Value.
  | VCVTSH2SS = 897
  /// Convert Low FP16 Value to Unsigned Integer.
  | VCVTSH2USI = 898
  /// Convert Signed Integer to Scalar Double Precision Floating-Point Value.
  | VCVTSI2SD = 899
  /// Convert a Signed Doubleword/Quadword Integer to an FP16 Value.
  | VCVTSI2SH = 900
  /// Convert Signed Integer to Scalar Single Precision Floating-Point Value.
  | VCVTSI2SS = 901
  /// Convert Scalar Single Precision Floating-Point Value to Scalar Double
  /// Precision Floating-Point Value.
  | VCVTSS2SD = 902
  /// Convert Low FP32 Value to an FP16 Value.
  | VCVTSS2SH = 903
  /// Convert Scalar Single Precision Floating-Point Value to Signed Integer.
  | VCVTSS2SI = 904
  /// Convert Scalar Single Precision Floating-Point Value to Unsigned
  /// Doubleword Integer.
  | VCVTSS2USI = 905
  /// Convert with Truncation Packed Double Precision Floating-Point Values to
  /// Packed Doubleword Integers.
  | VCVTTPD2DQ = 906
  /// Convert With Truncation Packed Double Precision Floating-Point Values to
  /// Packed Quadword Integers.
  | VCVTTPD2QQ = 907
  /// Convert With Truncation Packed Double Precision Floating-Point Values to
  /// Packed Unsigned Doubleword Integers.
  | VCVTTPD2UDQ = 908
  /// Convert With Truncation Packed Double Precision Floating-Point Values to
  /// Packed Unsigned Quadword Integers.
  | VCVTTPD2UQQ = 909
  /// Convert with Truncation Packed FP16 Values to Signed Doubleword Integers.
  | VCVTTPH2DQ = 910
  /// Convert with Truncation Packed FP16 Values to Signed Quadword Integers.
  | VCVTTPH2QQ = 911
  /// Convert with Truncation Packed FP16 Values to Unsigned Doubleword
  /// Integers.
  | VCVTTPH2UDQ = 912
  /// Convert with Truncation Packed FP16 Values to Unsigned Quadword Integers.
  | VCVTTPH2UQQ = 913
  /// Convert Packed FP16 Values to Unsigned Word Integers.
  | VCVTTPH2UW = 914
  /// Convert Packed FP16 Values to Signed Word Integers.
  | VCVTTPH2W = 915
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Signed Doubleword Integer Values.
  | VCVTTPS2DQ = 916
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Signed Quadword Integer Values.
  | VCVTTPS2QQ = 917
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Unsigned Doubleword Integer Values.
  | VCVTTPS2UDQ = 918
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Unsigned Quadword Integer Values.
  | VCVTTPS2UQQ = 919
  /// Convert With Truncation Scalar Double Precision Floating-Point Value to
  /// Signed Integer.
  | VCVTTSD2SI = 920
  /// Convert With Truncation Scalar Double Precision Floating-Point Value to
  /// Unsigned Integer.
  | VCVTTSD2USI = 921
  /// Convert with Truncation Low FP16 Value to a Signed Integer.
  | VCVTTSH2SI = 922
  /// Convert with Truncation Low FP16 Value to an Unsigned Integer.
  | VCVTTSH2USI = 923
  /// Convert With Truncation Scalar Single Precision Floating-Point Value to
  /// Signed Integer.
  | VCVTTSS2SI = 924
  /// Convert With Truncation Scalar Single Precision Floating-Point Value to
  /// Unsigned Integer.
  | VCVTTSS2USI = 925
  /// Convert Packed Unsigned Doubleword Integers to Packed Double Precision
  /// Floating-Point Values.
  | VCVTUDQ2PD = 926
  /// Convert Packed Unsigned Doubleword Integers to Packed FP16 Values.
  | VCVTUDQ2PH = 927
  /// Convert Packed Unsigned Doubleword Integers to Packed Single Precision
  /// Floating-Point Values.
  | VCVTUDQ2PS = 928
  /// Convert Packed Unsigned Quadword Integers to Packed Double Precision
  /// Floating-Point Values.
  | VCVTUQQ2PD = 929
  /// Convert Packed Unsigned Quadword Integers to Packed FP16 Values.
  | VCVTUQQ2PH = 930
  /// Convert Packed Unsigned Quadword Integers to Packed Single Precision
  /// Floating-Point Values.
  | VCVTUQQ2PS = 931
  /// Convert Unsigned Integer to Scalar Double Precision Floating-Point Value.
  | VCVTUSI2SD = 932
  /// Convert Unsigned Doubleword Integer to an FP16 Value.
  | VCVTUSI2SH = 933
  /// Convert Unsigned Integer to Scalar Single Precision Floating-Point Value.
  | VCVTUSI2SS = 934
  /// Convert Packed Unsigned Word Integers to FP16 Values.
  | VCVTUW2PH = 935
  /// Convert Packed Signed Word Integers to FP16 Values.
  | VCVTW2PH = 936
  /// Double Block Packed Sum-Absolute-Differences (SAD) on Unsigned Bytes.
  | VDBPSADBW = 937
  /// Divide Packed Double Precision Floating-Point Values.
  | VDIVPD = 938
  /// Divide Packed FP16 Values.
  | VDIVPH = 939
  /// Divide Packed Single Precision Floating-Point Values.
  | VDIVPS = 940
  /// Divide Scalar Double Precision Floating-Point Value.
  | VDIVSD = 941
  /// Divide Scalar FP16 Values.
  | VDIVSH = 942
  /// Divide Scalar Single Precision Floating-Point Values.
  | VDIVSS = 943
  /// Dot Product of BF16 Pairs Accumulated Into Packed Single Precision.
  | VDPBF16PS = 944
  /// Dot Product of Packed Double Precision Floating-Point Values.
  | VDPPD = 945
  /// Dot Product of Packed Single Precision Floating-Point Values.
  | VDPPS = 946
  /// Verify a Segment for Reading or Writing.
  | VERR = 947
  /// Verify a Segment for Reading or Writing.
  | VERW = 948
  /// Approximation to the Exponential 2^x of Packed Double Precision
  /// Floating-Point Values With Less Than 2^-23 Relative.
  | VEXP2PD = 949
  /// Approximation to the Exponential 2^x of Packed Single Precision
  /// Floating-Point Values With Less Than 2^-23 Relative Er-.
  | VEXP2PS = 950
  /// Load Sparse Packed Double Precision Floating-Point Values From Dense
  /// Memory.
  | VEXPANDPD = 951
  /// Load Sparse Packed Single Precision Floating-Point Values From Dense
  /// Memory.
  | VEXPANDPS = 952
  /// Extract Packed Floating-Point Values.
  | VEXTRACTF128 = 953
  /// VEXTRACTF32X4 xmm1/m128{k1}{z},ymm2,imm8: Extract 128 bits of packed
  /// single precision floating-point values from ymm2 and store results in
  /// xmm1/m128 subject to writemask k1.
  /// VEXTRACTF32x4 xmm1/m128{k1}{z},zmm2,imm8: Extract 128 bits of packed
  /// single precision floating-point values from zmm2 and store results in
  /// xmm1/m128 subject to writemask k1.
  | VEXTRACTF32X4 = 954
  /// Extract 256 bits of packed single precision floating-point values from
  /// zmm2 and store results in ymm1/m256 subject to writemask k1.
  | VEXTRACTF32X8 = 955
  /// VEXTRACTF64X2 xmm1/m128{k1}{z},ymm2,imm8: Extract 128 bits of packed
  /// double precision floating-point values from ymm2 and store results in
  /// xmm1/m128 subject to writemask k1.
  /// VEXTRACTF64X2 xmm1/m128{k1}{z},zmm2,imm8: Extract 128 bits of packed
  /// double precision floating-point values from zmm2 and store results in
  /// xmm1/m128 subject to writemask k1.
  | VEXTRACTF64X2 = 956
  /// Extract 256 bits of packed double precision floating-point values from
  /// zmm2 and store results in ymm1/m256 subject to writemask k1.
  | VEXTRACTF64X4 = 957
  /// Extract Packed Integer Values.
  | VEXTRACTI128 = 958
  /// VEXTRACTI32X4 xmm1/m128{k1}{z},ymm2,imm8: Extract 128 bits of double-word
  /// integer values from ymm2 and store results in xmm1/m128 subject to
  /// writemask k1.
  /// VEXTRACTI32x4 xmm1/m128{k1}{z},zmm2,imm8: Extract 128 bits of double-word
  /// integer values from zmm2 and store results in xmm1/m128 subject to
  /// writemask k1.
  | VEXTRACTI32X4 = 959
  /// Extract 256 bits of double-word integer values from zmm2 and store results
  /// in ymm1/m256 subject to writemask k1.
  | VEXTRACTI32X8 = 960
  /// VEXTRACTI64X2 xmm1/m128{k1}{z},ymm2,imm8: Extract 128 bits of quad-word
  /// integer values from ymm2 and store results in xmm1/m128 subject to
  /// writemask k1.
  /// VEXTRACTI64X2 xmm1/m128{k1}{z},zmm2,imm8: Extract 128 bits of quad-word
  /// integer values from zmm2 and store results in xmm1/m128 subject to
  /// writemask k1.
  | VEXTRACTI64X2 = 961
  /// Extract 256 bits of quad-word integer values from zmm2 and store results
  /// in ymm1/m256 subject to writemask k1.
  | VEXTRACTI64X4 = 962
  /// Extract Packed Floating-Point Values.
  | VEXTRACTPS = 963
  /// Complex Multiply and Accumulate FP16 Values.
  | VFCMADDCPH = 964
  /// Complex Multiply and Accumulate Scalar FP16 Values.
  | VFCMADDCSH = 965
  /// Complex Multiply FP16 Values.
  | VFCMULCPH = 966
  /// Complex Multiply Scalar FP16 Values.
  | VFCMULCSH = 967
  /// Fix Up Special Packed Float64 Values.
  | VFIXUPIMMPD = 968
  /// Fix Up Special Packed Float32 Values.
  | VFIXUPIMMPS = 969
  /// Fix Up Special Scalar Float64 Value.
  | VFIXUPIMMSD = 970
  /// Fix Up Special Scalar Float32 Value.
  | VFIXUPIMMSS = 971
  /// Fused Multiply-Add of Packed Double Precision Floating-Point Values.
  | VFMADD132PD = 972
  /// VFMADD132PH xmm1{k1}{z},xmm2,xmm3/m128/m16bcst: Multiply packed FP16
  /// values from xmm1 and xmm3/m128/m16bcst, add to xmm2, and store the result
  /// in xmm1.
  /// VFMADD132PH ymm1{k1}{z},ymm2,ymm3/m256/m16bcst: Multiply packed FP16
  /// values from ymm1 and ymm3/m256/m16bcst, add to ymm2, and store the result
  /// in ymm1.
  /// VFMADD132PH zmm1{k1}{z},zmm2,zmm3/m512/m16bcst{er}: Multiply packed FP16
  /// values from zmm1 and zmm3/m512/m16bcst, add to zmm2, and store the result
  /// in zmm1.
  | VFMADD132PH = 973
  /// Fused Multiply-Add of Packed Single Precision Floating-Point Values.
  | VFMADD132PS = 974
  /// Fused Multiply-Add of Scalar Double Precision Floating-Point Values.
  | VFMADD132SD = 975
  /// Multiply FP16 values from xmm1 and xmm3/m16, add to xmm2, and store the
  /// result in xmm1.
  | VFMADD132SH = 976
  /// Fused Multiply-Add of Scalar Single Precision Floating-Point Values.
  | VFMADD132SS = 977
  /// Fused Multiply-Add of Packed Double Precision Floating-Point Values.
  | VFMADD213PD = 978
  /// VFMADD213PH xmm1{k1}{z},xmm2,xmm3/m128/m16bcst: Multiply packed FP16
  /// values from xmm1 and xmm2, add to xmm3/m128/m16bcst, and store the result
  /// in xmm1.
  /// VFMADD213PH ymm1{k1}{z},ymm2,ymm3/m256/m16bcst: Multiply packed FP16
  /// values from ymm1 and ymm2, add to ymm3/m256/m16bcst, and store the result
  /// in ymm1.
  /// VFMADD213PH zmm1{k1}{z},zmm2,zmm3/m512/m16bcst{er}: Multiply packed FP16
  /// values from zmm1 and zmm2, add to zmm3/m512/m16bcst, and store the result
  /// in zmm1.
  | VFMADD213PH = 979
  /// Fused Multiply-Add of Packed Single Precision Floating-Point Values.
  | VFMADD213PS = 980
  /// Fused Multiply-Add of Scalar Double Precision Floating-Point Values.
  | VFMADD213SD = 981
  /// Multiply FP16 values from xmm1 and xmm2, add to xmm3/m16, and store the
  /// result in xmm1.
  | VFMADD213SH = 982
  /// Fused Multiply-Add of Scalar Single Precision Floating-Point Values.
  | VFMADD213SS = 983
  /// Fused Multiply-Add of Packed Double Precision Floating-Point Values.
  | VFMADD231PD = 984
  /// VFMADD231PH xmm1{k1}{z},xmm2,xmm3/m128/m16bcst: Multiply packed FP16
  /// values from xmm2 and xmm3/m128/m16bcst, add to xmm1, and store the result
  /// in xmm1.
  /// VFMADD231PH ymm1{k1}{z},ymm2,ymm3/m256/m16bcst: Multiply packed FP16
  /// values from ymm2 and ymm3/m256/m16bcst, add to ymm1, and store the result
  /// in ymm1.
  /// VFMADD231PH zmm1{k1}{z},zmm2,zmm3/m512/m16bcst{er}: Multiply packed FP16
  /// values from zmm2 and zmm3/m512/m16bcst, add to zmm1, and store the result
  /// in zmm1.
  | VFMADD231PH = 985
  /// Fused Multiply-Add of Packed Single Precision Floating-Point Values.
  | VFMADD231PS = 986
  /// Fused Multiply-Add of Scalar Double Precision Floating-Point Values.
  | VFMADD231SD = 987
  /// Multiply FP16 values from xmm2 and xmm3/m16, add to xmm1, and store the
  /// result in xmm1.
  | VFMADD231SH = 988
  /// Fused Multiply-Add of Scalar Single Precision Floating-Point Values.
  | VFMADD231SS = 989
  /// Complex Multiply and Accumulate FP16 Values.
  | VFMADDCPH = 990
  /// Complex Multiply and Accumulate Scalar FP16 Values.
  | VFMADDCSH = 991
  /// Multiply and Add Packed Double-Precision Floating-Point(Only AMD).
  | VFMADDPD = 992
  /// Multiply and Add Packed Single-Precision Floating-Point(Only AMD).
  | VFMADDPS = 993
  /// Multiply and Add Scalar Double-Precision Floating-Point(Only AMD).
  | VFMADDSD = 994
  /// Multiply and Add Scalar Single-Precision Floating-Point(Only AMD).
  | VFMADDSS = 995
  /// Fused Multiply-Alternating Add/Subtract of Packed Double Precision
  /// Floating-Point Values.
  | VFMADDSUB132PD = 996
  /// Fused Multiply-Alternating Add/Subtract of Packed FP16 Values.
  | VFMADDSUB132PH = 997
  /// Fused Multiply-Alternating Add/Subtract of Packed Single Precision
  /// Floating-Point Values.
  | VFMADDSUB132PS = 998
  /// Fused Multiply-Alternating Add/Subtract of Packed Double Precision
  /// Floating-Point Values.
  | VFMADDSUB213PD = 999
  /// Fused Multiply-Alternating Add/Subtract of Packed FP16 Values.
  | VFMADDSUB213PH = 1000
  /// Fused Multiply-Alternating Add/Subtract of Packed Single Precision
  /// Floating-Point Values.
  | VFMADDSUB213PS = 1001
  /// Fused Multiply-Alternating Add/Subtract of Packed Double Precision
  /// Floating-Point Values.
  | VFMADDSUB231PD = 1002
  /// Fused Multiply-Alternating Add/Subtract of Packed FP16 Values.
  | VFMADDSUB231PH = 1003
  /// Fused Multiply-Alternating Add/Subtract of Packed Single Precision
  /// Floating-Point Values.
  | VFMADDSUB231PS = 1004
  /// Fused Multiply-Subtract of Packed Double Precision Floating-Point Values.
  | VFMSUB132PD = 1005
  /// VFMSUB132PH xmm1{k1}{z},xmm2,xmm3/m128/m16bcst: Multiply packed FP16
  /// values from xmm1 and xmm3/m128/m16bcst, subtract xmm2, and store the
  /// result in xmm1 subject to writemask k1.
  /// VFMSUB132PH ymm1{k1}{z},ymm2,ymm3/m256/m16bcst: Multiply packed FP16
  /// values from ymm1 and ymm3/m256/m16bcst, subtract ymm2, and store the
  /// result in ymm1 subject to writemask k1.
  /// VFMSUB132PH zmm1{k1}{z},zmm2,zmm3/m512/m16bcst{er}: Multiply packed FP16
  /// values from zmm1 and zmm3/m512/m16bcst, subtract zmm2, and store the
  /// result in zmm1 subject to writemask k1.
  | VFMSUB132PH = 1006
  /// Fused Multiply-Subtract of Packed Single Precision Floating-Point Values.
  | VFMSUB132PS = 1007
  /// Fused Multiply-Subtract of Scalar Double Precision Floating-Point Values.
  | VFMSUB132SD = 1008
  /// Multiply FP16 values from xmm1 and xmm3/m16, subtract xmm2, and store the
  /// result in xmm1 subject to writemask k1.
  | VFMSUB132SH = 1009
  /// Fused Multiply-Subtract of Scalar Single Precision Floating-Point Values.
  | VFMSUB132SS = 1010
  /// Fused Multiply-Subtract of Packed Double Precision Floating-Point Values.
  | VFMSUB213PD = 1011
  /// VFMSUB213PH xmm1{k1}{z},xmm2,xmm3/m128/m16bcst: Multiply packed FP16
  /// values from xmm1 and xmm2, subtract xmm3/m128/m16bcst, and store the
  /// result in xmm1 subject to writemask k1.
  /// VFMSUB213PH ymm1{k1}{z},ymm2,ymm3/m256/m16bcst: Multiply packed FP16
  /// values from ymm1 and ymm2, subtract ymm3/m256/m16bcst, and store the
  /// result in ymm1 subject to writemask k1.
  /// VFMSUB213PH zmm1{k1}{z},zmm2,zmm3/m512/m16bcst{er}: Multiply packed FP16
  /// values from zmm1 and zmm2, subtract zmm3/m512/m16bcst, and store the
  /// result in zmm1 subject to writemask k1.
  | VFMSUB213PH = 1012
  /// Fused Multiply-Subtract of Packed Single Precision Floating-Point Values.
  | VFMSUB213PS = 1013
  /// Fused Multiply-Subtract of Scalar Double Precision Floating-Point Values.
  | VFMSUB213SD = 1014
  /// Multiply FP16 values from xmm1 and xmm2, subtract xmm3/m16, and store the
  /// result in xmm1 subject to writemask k1.
  | VFMSUB213SH = 1015
  /// Fused Multiply-Subtract of Scalar Single Precision Floating-Point Values.
  | VFMSUB213SS = 1016
  /// Fused Multiply-Subtract of Packed Double Precision Floating-Point Values.
  | VFMSUB231PD = 1017
  /// VFMSUB231PH xmm1{k1}{z},xmm2,xmm3/m128/m16bcst: Multiply packed FP16
  /// values from xmm2 and xmm3/m128/m16bcst, subtract xmm1, and store the
  /// result in xmm1 subject to writemask k1.
  /// VFMSUB231PH ymm1{k1}{z},ymm2,ymm3/m256/m16bcst: Multiply packed FP16
  /// values from ymm2 and ymm3/m256/m16bcst, subtract ymm1, and store the
  /// result in ymm1 subject to writemask k1.
  /// VFMSUB231PH zmm1{k1}{z},zmm2,zmm3/m512/m16bcst{er}: Multiply packed FP16
  /// values from zmm2 and zmm3/m512/m16bcst, subtract zmm1, and store the
  /// result in zmm1 subject to writemask k1.
  | VFMSUB231PH = 1018
  /// Fused Multiply-Subtract of Packed Single Precision Floating-Point Values.
  | VFMSUB231PS = 1019
  /// Fused Multiply-Subtract of Scalar Double Precision Floating-Point Values.
  | VFMSUB231SD = 1020
  /// Multiply FP16 values from xmm2 and xmm3/m16, subtract xmm1, and store the
  /// result in xmm1 subject to writemask k1.
  | VFMSUB231SH = 1021
  /// Fused Multiply-Subtract of Scalar Single Precision Floating-Point Values.
  | VFMSUB231SS = 1022
  /// Fused Multiply-Alternating Subtract/Add of Packed Double Precision
  /// Floating-Point Values.
  | VFMSUBADD132PD = 1023
  /// Fused Multiply-Alternating Subtract/Add of Packed FP16 Values.
  | VFMSUBADD132PH = 1024
  /// Fused Multiply-Alternating Subtract/Add of Packed Single Precision
  /// Floating-Point Values.
  | VFMSUBADD132PS = 1025
  /// Fused Multiply-Alternating Subtract/Add of Packed Double Precision
  /// Floating-Point Values.
  | VFMSUBADD213PD = 1026
  /// Fused Multiply-Alternating Subtract/Add of Packed FP16 Values.
  | VFMSUBADD213PH = 1027
  /// Fused Multiply-Alternating Subtract/Add of Packed Single Precision
  /// Floating-Point Values.
  | VFMSUBADD213PS = 1028
  /// Fused Multiply-Alternating Subtract/Add of Packed Double Precision
  /// Floating-Point Values.
  | VFMSUBADD231PD = 1029
  /// Fused Multiply-Alternating Subtract/Add of Packed FP16 Values.
  | VFMSUBADD231PH = 1030
  /// Fused Multiply-Alternating Subtract/Add of Packed Single Precision
  /// Floating-Point Values.
  | VFMSUBADD231PS = 1031
  /// Complex Multiply FP16 Values.
  | VFMULCPH = 1032
  /// Complex Multiply Scalar FP16 Values.
  | VFMULCSH = 1033
  /// Fused Negative Multiply-Add of Packed Double Precision Floating-Point
  /// Values.
  | VFNMADD132PD = 1034
  /// VFNMADD132PH xmm1{k1}{z},xmm2,xmm3/m128/m16bcst: Multiply packed FP16
  /// values from xmm1 and xmm3/m128/m16bcst, and negate the value. Add this
  /// value to xmm2, and store the result in xmm1.
  /// VFNMADD132PH ymm1{k1}{z},ymm2,ymm3/m256/m16bcst: Multiply packed FP16
  /// values from ymm1 and ymm3/m256/m16bcst, and negate the value. Add this
  /// value to ymm2, and store the result in ymm1.
  /// VFNMADD132PH zmm1{k1}{z},zmm2,zmm3/m512/m16bcst{er}: Multiply packed FP16
  /// values from zmm1 and zmm3/m512/m16bcst, and negate the value. Add this
  /// value to zmm2, and store the result in zmm1.
  | VFNMADD132PH = 1035
  /// Fused Negative Multiply-Add of Packed Single Precision Floating-Point
  /// Values.
  | VFNMADD132PS = 1036
  /// Fused Negative Multiply-Add of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMADD132SD = 1037
  /// Multiply FP16 values from xmm1 and xmm3/m16, and negate the value. Add
  /// this value to xmm2, and store the result in xmm1.
  | VFNMADD132SH = 1038
  /// Fused Negative Multiply-Add of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMADD132SS = 1039
  /// Fused Negative Multiply-Add of Packed Double Precision Floating-Point
  /// Values.
  | VFNMADD213PD = 1040
  /// VFNMADD213PH xmm1{k1}{z},xmm2,xmm3/m128/m16bcst: Multiply packed FP16
  /// values from xmm1 and xmm2, and negate the value. Add this value to
  /// xmm3/m128/m16bcst, and store the result in xmm1.
  /// VFNMADD213PH ymm1{k1}{z},ymm2,ymm3/m256/m16bcst: Multiply packed FP16
  /// values from ymm1 and ymm2, and negate the value. Add this value to
  /// ymm3/m256/m16bcst, and store the result in ymm1.
  /// VFNMADD213PH zmm1{k1}{z},zmm2,zmm3/m512/m16bcst{er}: Multiply packed FP16
  /// values from zmm1 and zmm2, and negate the value. Add this value to
  /// zmm3/m512/m16bcst, and store the result in zmm1.
  | VFNMADD213PH = 1041
  /// Fused Negative Multiply-Add of Packed Single Precision Floating-Point
  /// Values.
  | VFNMADD213PS = 1042
  /// Fused Negative Multiply-Add of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMADD213SD = 1043
  /// Multiply FP16 values from xmm1 and xmm2, and negate the value. Add this
  /// value to xmm3/m16, and store the result in xmm1.
  | VFNMADD213SH = 1044
  /// Fused Negative Multiply-Add of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMADD213SS = 1045
  /// Fused Negative Multiply-Add of Packed Double Precision Floating-Point
  /// Values.
  | VFNMADD231PD = 1046
  /// VFNMADD231PH xmm1{k1}{z},xmm2,xmm3/m128/m16bcst: Multiply packed FP16
  /// values from xmm2 and xmm3/m128/m16bcst, and negate the value. Add this
  /// value to xmm1, and store the result in xmm1.
  /// VFNMADD231PH ymm1{k1}{z},ymm2,ymm3/m256/m16bcst: Multiply packed FP16
  /// values from ymm2 and ymm3/m256/m16bcst, and negate the value. Add this
  /// value to ymm1, and store the result in ymm1.
  /// VFNMADD231PH zmm1{k1}{z},zmm2,zmm3/m512/m16bcst{er}: Multiply packed FP16
  /// values from zmm2 and zmm3/m512/m16bcst, and negate the value. Add this
  /// value to zmm1, and store the result in zmm1.
  | VFNMADD231PH = 1047
  /// Fused Negative Multiply-Add of Packed Single Precision Floating-Point
  /// Values.
  | VFNMADD231PS = 1048
  /// Fused Negative Multiply-Add of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMADD231SD = 1049
  /// Multiply FP16 values from xmm2 and xmm3/m16, and negate the value. Add
  /// this value to xmm1, and store the result in xmm1.
  | VFNMADD231SH = 1050
  /// Fused Negative Multiply-Add of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMADD231SS = 1051
  /// Fused Negative Multiply-Subtract of Packed Double Precision Floating-Point
  /// Values.
  | VFNMSUB132PD = 1052
  /// VFNMSUB132PH xmm1{k1}{z},xmm2,xmm3/m128/m16bcst: Multiply packed FP16
  /// values from xmm1 and xmm3/m128/m16bcst, and negate the value. Subtract
  /// xmm2 from this value, and store the result in xmm1 subject to writemask
  /// k1.
  /// VFNMSUB132PH ymm1{k1}{z},ymm2,ymm3/m256/m16bcst: Multiply packed FP16
  /// values from ymm1 and ymm3/m256/m16bcst, and negate the value. Subtract
  /// ymm2 from this value, and store the result in ymm1 subject to writemask
  /// k1.
  /// VFNMSUB132PH zmm1{k1}{z},zmm2,zmm3/m512/m16bcst{er}: Multiply packed FP16
  /// values from zmm1 and zmm3/m512/m16bcst, and negate the value. Subtract
  /// zmm2 from this value, and store the result in zmm1 subject to writemask
  /// k1.
  | VFNMSUB132PH = 1053
  /// Fused Negative Multiply-Subtract of Packed Single Precision Floating-Point
  /// Val-.
  | VFNMSUB132PS = 1054
  /// Fused Negative Multiply-Subtract of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMSUB132SD = 1055
  /// Multiply FP16 values from xmm1 and xmm3/m16, and negate the value.
  /// Subtract xmm2 from this value, and store the result in xmm1 subject to
  /// writemask k1.
  | VFNMSUB132SH = 1056
  /// Fused Negative Multiply-Subtract of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMSUB132SS = 1057
  /// Fused Negative Multiply-Subtract of Packed Double Precision Floating-Point
  /// Values.
  | VFNMSUB213PD = 1058
  /// VFNMSUB213PH xmm1{k1}{z},xmm2,xmm3/m128/m16bcst: Multiply packed FP16
  /// values from xmm1 and xmm2, and negate the value. Subtract
  /// xmm3/m128/m16bcst from this value, and store the result in xmm1 subject to
  /// writemask k1.
  /// VFNMSUB213PH ymm1{k1}{z},ymm2,ymm3/m256/m16bcst: Multiply packed FP16
  /// values from ymm1 and ymm2, and negate the value. Subtract
  /// ymm3/m256/m16bcst from this value, and store the result in ymm1 subject to
  /// writemask k1.
  /// VFNMSUB213PH zmm1{k1}{z},zmm2,zmm3/m512/m16bcst{er}: Multiply packed FP16
  /// values from zmm1 and zmm2, and negate the value. Subtract
  /// zmm3/m512/m16bcst from this value, and store the result in zmm1 subject to
  /// writemask k1.
  | VFNMSUB213PH = 1059
  /// Fused Negative Multiply-Subtract of Packed Single Precision Floating-Point
  /// Val-.
  | VFNMSUB213PS = 1060
  /// Fused Negative Multiply-Subtract of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMSUB213SD = 1061
  /// Multiply FP16 values from xmm1 and xmm2, and negate the value. Subtract
  /// xmm3/m16 from this value, and store the result in xmm1 subject to
  /// writemask k1.
  | VFNMSUB213SH = 1062
  /// Fused Negative Multiply-Subtract of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMSUB213SS = 1063
  /// Fused Negative Multiply-Subtract of Packed Double Precision Floating-Point
  /// Values.
  | VFNMSUB231PD = 1064
  /// VFNMSUB231PH xmm1{k1}{z},xmm2,xmm3/m128/m16bcst: Multiply packed FP16
  /// values from xmm2 and xmm3/m128/m16bcst, and negate the value. Subtract
  /// xmm1 from this value, and store the result in xmm1 subject to writemask
  /// k1.
  /// VFNMSUB231PH ymm1{k1}{z},ymm2,ymm3/m256/m16bcst: Multiply packed FP16
  /// values from ymm2 and ymm3/m256/m16bcst, and negate the value. Subtract
  /// ymm1 from this value, and store the result in ymm1 subject to writemask
  /// k1.
  /// VFNMSUB231PH zmm1{k1}{z},zmm2,zmm3/m512/m16bcst{er}: Multiply packed FP16
  /// values from zmm2 and zmm3/m512/m16bcst, and negate the value. Subtract
  /// zmm1 from this value, and store the result in zmm1 subject to writemask
  /// k1.
  | VFNMSUB231PH = 1065
  /// Fused Negative Multiply-Subtract of Packed Single Precision Floating-Point
  /// Val-.
  | VFNMSUB231PS = 1066
  /// Fused Negative Multiply-Subtract of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMSUB231SD = 1067
  /// Multiply FP16 values from xmm2 and xmm3/m16, and negate the value.
  /// Subtract xmm1 from this value, and store the result in xmm1 subject to
  /// writemask k1.
  | VFNMSUB231SH = 1068
  /// Fused Negative Multiply-Subtract of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMSUB231SS = 1069
  /// Tests Types of Packed Float64 Values.
  | VFPCLASSPD = 1070
  /// Test Types of Packed FP16 Values.
  | VFPCLASSPH = 1071
  /// Tests Types of Packed Float32 Values.
  | VFPCLASSPS = 1072
  /// Tests Type of a Scalar Float64 Value.
  | VFPCLASSSD = 1073
  /// Test Types of Scalar FP16 Values.
  | VFPCLASSSH = 1074
  /// Tests Type of a Scalar Float32 Value.
  | VFPCLASSSS = 1075
  /// Gather Packed Double Precision Floating-Point Values Using Signed
  /// Dword/Qword Indices.
  | VGATHERDPD = 1076
  /// Gather Packed Single Precision Floating-Point Values Using Signed
  /// Dword/Qword Indices.
  | VGATHERDPS = 1077
  /// Sparse Prefetch Packed SP/DP Data Values With Signed.
  | VGATHERPF0DPD = 1078
  /// Sparse Prefetch Packed SP/DP Data Values With Signed.
  | VGATHERPF0DPS = 1079
  /// Sparse Prefetch Packed SP/DP Data Values With Signed.
  | VGATHERPF0QPD = 1080
  /// Sparse Prefetch Packed SP/DP Data Values With Signed.
  | VGATHERPF0QPS = 1081
  /// Sparse Prefetch Packed SP/DP Data Values With Signed.
  | VGATHERPF1DPD = 1082
  /// Sparse Prefetch Packed SP/DP Data Values With Signed.
  | VGATHERPF1DPS = 1083
  /// Sparse Prefetch Packed SP/DP Data Values With Signed.
  | VGATHERPF1QPD = 1084
  /// Sparse Prefetch Packed SP/DP Data Values With Signed.
  | VGATHERPF1QPS = 1085
  /// Gather Packed Double Precision Floating-Point Values Using Signed
  /// Dword/Qword Indices.
  | VGATHERQPD = 1086
  /// Gather Packed Single Precision Floating-Point Values Using Signed
  /// Dword/Qword Indices.
  | VGATHERQPS = 1087
  /// Convert Exponents of Packed Double Precision Floating-Point Values to
  /// Double Precision Floating-Point Values.
  | VGETEXPPD = 1088
  /// Convert Exponents of Packed FP16 Values to FP16 Values.
  | VGETEXPPH = 1089
  /// Convert Exponents of Packed Single Precision Floating-Point Values to
  /// Single Precision Floating-Point Values.
  | VGETEXPPS = 1090
  /// Convert Exponents of Scalar Double Precision Floating-Point Value to
  /// Double Precision Floating-Point Value.
  | VGETEXPSD = 1091
  /// Convert Exponents of Scalar FP16 Values to FP16 Values.
  | VGETEXPSH = 1092
  /// Convert Exponents of Scalar Single Precision Floating-Point Value to
  /// Single Precision Floating-Point Value.
  | VGETEXPSS = 1093
  /// Extract Float64 Vector of Normalized Mantissas From Float64 Vector.
  | VGETMANTPD = 1094
  /// Extract FP16 Vector of Normalized Mantissas from FP16 Vector.
  | VGETMANTPH = 1095
  /// Extract Float32 Vector of Normalized Mantissas From Float32 Vector.
  | VGETMANTPS = 1096
  /// Extract Float64 of Normalized Mantissa From Float64 Scalar.
  | VGETMANTSD = 1097
  /// Extract FP16 of Normalized Mantissa from FP16 Scalar.
  | VGETMANTSH = 1098
  /// Extract Float32 Vector of Normalized Mantissa From Float32 Scalar.
  | VGETMANTSS = 1099
  /// Galois Field Affine Transformation Inverse.
  | VGF2P8AFFINEINVQB = 1100
  /// Galois Field Affine Transformation.
  | VGF2P8AFFINEQB = 1101
  /// Galois Field Multiply Bytes.
  | VGF2P8MULB = 1102
  /// Packed Double Precision Floating-Point Horizontal Add.
  | VHADDPD = 1103
  /// Packed Single Precision Floating-Point Horizontal Add.
  | VHADDPS = 1104
  /// Packed Double Precision Floating-Point Horizontal Subtract.
  | VHSUBPD = 1105
  /// Packed Single Precision Floating-Point Horizontal Subtract.
  | VHSUBPS = 1106
  /// Insert Packed Floating-Point Values.
  | VINSERTF128 = 1107
  /// VINSERTF32X4 ymm1{k1}{z},ymm2,xmm3/m128,imm8: Insert 128 bits of packed
  /// single-precision floating-point values from xmm3/m128 and the remaining
  /// values from ymm2 into ymm1 under writemask k1.
  /// VINSERTF32X4 zmm1{k1}{z},zmm2,xmm3/m128,imm8: Insert 128 bits of packed
  /// single-precision floating-point values from xmm3/m128 and the remaining
  /// values from zmm2 into zmm1 under writemask k1.
  | VINSERTF32X4 = 1108
  /// Insert 256 bits of packed single-precision floating-point values from
  /// ymm3/m256 and the remaining values from zmm2 into zmm1 under writemask k1.
  | VINSERTF32X8 = 1109
  /// VINSERTF64X2 ymm1{k1}{z},ymm2,xmm3/m128,imm8: Insert 128 bits of packed
  /// double precision floating-point values from xmm3/m128 and the remaining
  /// values from ymm2 into ymm1 under writemask k1.
  /// VINSERTF64X2 zmm1{k1}{z},zmm2,xmm3/m128,imm8: Insert 128 bits of packed
  /// double precision floating-point values from xmm3/m128 and the remaining
  /// values from zmm2 into zmm1 under writemask k1.
  | VINSERTF64X2 = 1110
  /// Insert 256 bits of packed double precision floating-point values from
  /// ymm3/m256 and the remaining values from zmm2 into zmm1 under writemask k1.
  | VINSERTF64X4 = 1111
  /// Insert Packed Integer Values.
  | VINSERTI128 = 1112
  /// VINSERTI32X4 ymm1{k1}{z},ymm2,xmm3/m128,imm8: Insert 128 bits of packed
  /// doubleword integer values from xmm3/m128 and the remaining values from
  /// ymm2 into ymm1 under writemask k1.
  /// VINSERTI32X4 zmm1{k1}{z},zmm2,xmm3/m128,imm8: Insert 128 bits of packed
  /// doubleword integer values from xmm3/m128 and the remaining values from
  /// zmm2 into zmm1 under writemask k1.
  | VINSERTI32X4 = 1113
  /// Insert 256 bits of packed doubleword integer values from ymm3/m256 and the
  /// remaining values from zmm2 into zmm1 under writemask k1.
  | VINSERTI32X8 = 1114
  /// VINSERTI64X2 ymm1{k1}{z},ymm2,xmm3/m128,imm8: Insert 128 bits of packed
  /// quadword integer values from xmm3/m128 and the remaining values from ymm2
  /// into ymm1 under writemask k1.
  /// VINSERTI64X2 zmm1{k1}{z},zmm2,xmm3/m128,imm8: Insert 128 bits of packed
  /// quadword integer values from xmm3/m128 and the remaining values from zmm2
  /// into zmm1 under writemask k1.
  | VINSERTI64X2 = 1115
  /// Insert 256 bits of packed quadword integer values from ymm3/m256 and the
  /// remaining values from zmm2 into zmm1 under writemask k1.
  | VINSERTI64X4 = 1116
  /// Insert Scalar Single Precision Floating-Point Value.
  | VINSERTPS = 1117
  /// Load Unaligned Integer 128 Bits.
  | VLDDQU = 1118
  /// Load MXCSR Register.
  | VLDMXCSR = 1119
  /// Store Selected Bytes of Double Quadword.
  | VMASKMOVDQU = 1120
  /// VMASKMOVPD xmm1,xmm2,m128: Conditionally load packed double precision
  /// values from m128 using mask in xmm2 and store in xmm1.
  /// VMASKMOVPD ymm1,ymm2,m256: Conditionally load packed double precision
  /// values from m256 using mask in ymm2 and store in ymm1.
  /// VMASKMOVPD m128,xmm1,xmm2: Conditionally store packed double precision
  /// values from xmm2 using mask in xmm1.
  /// VMASKMOVPD m256,ymm1,ymm2: Conditionally store packed double precision
  /// values from ymm2 using mask in ymm1.
  | VMASKMOVPD = 1121
  /// VMASKMOVPS xmm1,xmm2,m128: Conditionally load packed single precision
  /// values from m128 using mask in xmm2 and store in xmm1.
  /// VMASKMOVPS ymm1,ymm2,m256: Conditionally load packed single precision
  /// values from m256 using mask in ymm2 and store in ymm1.
  /// VMASKMOVPS m128,xmm1,xmm2: Conditionally store packed single precision
  /// values from xmm2 using mask in xmm1.
  /// VMASKMOVPS m256,ymm1,ymm2: Conditionally store packed single precision
  /// values from ymm2 using mask in ymm1.
  | VMASKMOVPS = 1122
  /// Maximum of Packed Double Precision Floating-Point Values.
  | VMAXPD = 1123
  /// Return Maximum of Packed FP16 Values.
  | VMAXPH = 1124
  /// Maximum of Packed Single Precision Floating-Point Values.
  | VMAXPS = 1125
  /// Return Maximum Scalar Double Precision Floating-Point Value.
  | VMAXSD = 1126
  /// Return Maximum of Scalar FP16 Values.
  | VMAXSH = 1127
  /// Return Maximum Scalar Single Precision Floating-Point Value.
  | VMAXSS = 1128
  /// Call to VM Monitor.
  | VMCALL = 1129
  /// Clear Virtual-Machine Control Structure.
  | VMCLEAR = 1130
  /// Invoke VM function.
  | VMFUNC = 1131
  /// Minimum of Packed Double Precision Floating-Point Values.
  | VMINPD = 1132
  /// Return Minimum of Packed FP16 Values.
  | VMINPH = 1133
  /// Minimum of Packed Single Precision Floating-Point Values.
  | VMINPS = 1134
  /// Return Minimum Scalar Double Precision Floating-Point Value.
  | VMINSD = 1135
  /// Return Minimum Scalar FP16 Value.
  | VMINSH = 1136
  /// Return Minimum Scalar Single Precision Floating-Point Value.
  | VMINSS = 1137
  /// Launch Virtual Machine.
  | VMLAUNCH = 1138
  /// Move Aligned Packed Double Precision Floating-Point Values.
  | VMOVAPD = 1139
  /// Move Aligned Packed Single Precision Floating-Point Values.
  | VMOVAPS = 1140
  /// Move Doubleword/Move Quadword.
  | VMOVD = 1141
  /// Replicate Double Precision Floating-Point Values.
  | VMOVDDUP = 1142
  /// Move Aligned Packed Integer Values.
  | VMOVDQA = 1143
  /// Move Aligned Packed Integer Values.
  | VMOVDQA32 = 1144
  /// Move Aligned Packed Integer Values.
  | VMOVDQA64 = 1145
  /// Move Unaligned Packed Integer Values.
  | VMOVDQU = 1146
  /// Move Unaligned Packed Integer Values.
  | VMOVDQU16 = 1147
  /// Move Unaligned Packed Integer Values.
  | VMOVDQU32 = 1148
  /// Move Unaligned Packed Integer Values.
  | VMOVDQU64 = 1149
  /// Move Unaligned Packed Integer Values.
  | VMOVDQU8 = 1150
  /// Move Packed Single Precision Floating-Point Values High to Low.
  | VMOVHLPS = 1151
  /// Move High Packed Double Precision Floating-Point Value.
  | VMOVHPD = 1152
  /// Move High Packed Single Precision Floating-Point Values.
  | VMOVHPS = 1153
  /// Move Packed Single Precision Floating-Point Values Low to High.
  | VMOVLHPS = 1154
  /// Move Low Packed Double Precision Floating-Point Value.
  | VMOVLPD = 1155
  /// Move Low Packed Single Precision Floating-Point Values.
  | VMOVLPS = 1156
  /// Extract Packed Double Precision Floating-Point Sign Mask.
  | VMOVMSKPD = 1157
  /// Extract Packed Single Precision Floating-Point Sign Mask.
  | VMOVMSKPS = 1158
  /// Store Packed Integers Using Non-Temporal Hint.
  | VMOVNTDQ = 1159
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | VMOVNTDQA = 1160
  /// Store Packed Double Precision Floating-Point Values Using Non-Temporal
  /// Hint.
  | VMOVNTPD = 1161
  /// Store Packed Single Precision Floating-Point Values Using Non-Temporal
  /// Hint.
  | VMOVNTPS = 1162
  /// Move Doubleword/Move Quadword.
  | VMOVQ = 1163
  /// Move or Merge Scalar Double Precision Floating-Point Value.
  | VMOVSD = 1164
  /// Move Scalar FP16 Value.
  | VMOVSH = 1165
  /// Replicate Single Precision Floating-Point Values.
  | VMOVSHDUP = 1166
  /// Replicate Single Precision Floating-Point Values.
  | VMOVSLDUP = 1167
  /// Move or Merge Scalar Single Precision Floating-Point Value.
  | VMOVSS = 1168
  /// Move Unaligned Packed Double Precision Floating-Point Values.
  | VMOVUPD = 1169
  /// Move Unaligned Packed Single Precision Floating-Point Values.
  | VMOVUPS = 1170
  /// Move to/from Control Registers.
  | VMOVW = 1171
  /// Compute Multiple Packed Sums of Absolute Difference.
  | VMPSADBW = 1172
  /// Load Pointer to Virtual-Machine Control Structure.
  | VMPTRLD = 1173
  /// Store Pointer to Virtual-Machine Control Structure.
  | VMPTRST = 1174
  /// Reads a component from the VMCS and stores it into a destination operand.
  | VMREAD = 1175
  /// Resume Virtual Machine.
  | VMRESUME = 1176
  /// Multiply Packed Double Precision Floating-Point Values.
  | VMULPD = 1177
  /// Multiply Packed FP16 Values.
  | VMULPH = 1178
  /// Multiply Packed Single Precision Floating-Point Values.
  | VMULPS = 1179
  /// Multiply Scalar Double Precision Floating-Point Value.
  | VMULSD = 1180
  /// Multiply Scalar FP16 Values.
  | VMULSH = 1181
  /// Multiply Scalar Single Precision Floating-Point Values.
  | VMULSS = 1182
  /// Leave VMX Operation.
  | VMXOFF = 1183
  /// Enter VMX Operation.
  | VMXON = 1184
  /// Bitwise Logical OR of Packed Double Precision Floating-Point Values.
  | VORPD = 1185
  /// Bitwise Logical OR of Packed Single Precision Floating-Point Values.
  | VORPS = 1186
  /// Compute Intersection Between DWORDS/QUADWORDS to a Pair of Mask Registers.
  | VP2INTERSECTD = 1187
  /// Compute Intersection Between DWORDS/QUADWORDS to a Pair of Mask Registers.
  | VP2INTERSECTQ = 1188
  /// Dot Product of Signed Words With Dword Accumulation (4-Iterations).
  | VP4DPWSSD = 1189
  /// Dot Product of Signed Words With Dword Accumulation and Saturation
  /// (4-Iterations).
  | VP4DPWSSDS = 1190
  /// Packed Absolute Value.
  | VPABSB = 1191
  /// Packed Absolute Value.
  | VPABSD = 1192
  /// Packed Absolute Value.
  | VPABSQ = 1193
  /// Packed Absolute Value.
  | VPABSW = 1194
  /// Pack With Signed Saturation.
  | VPACKSSDW = 1195
  /// Pack With Signed Saturation.
  | VPACKSSWB = 1196
  /// Pack With Unsigned Saturation.
  | VPACKUSDW = 1197
  /// Pack With Unsigned Saturation.
  | VPACKUSWB = 1198
  /// Add Packed Integers.
  | VPADDB = 1199
  /// Add Packed Integers.
  | VPADDD = 1200
  /// Add Packed Integers.
  | VPADDQ = 1201
  /// Add Packed Signed Integers with Signed Saturation.
  | VPADDSB = 1202
  /// Add Packed Signed Integers with Signed Saturation.
  | VPADDSW = 1203
  /// Add Packed Unsigned Integers With Unsigned Saturation.
  | VPADDUSB = 1204
  /// Add Packed Unsigned Integers With Unsigned Saturation.
  | VPADDUSW = 1205
  /// Add Packed Integers.
  | VPADDW = 1206
  /// Packed Align Right.
  | VPALIGNR = 1207
  /// Logical AND.
  | VPAND = 1208
  /// Logical AND.
  | VPANDD = 1209
  /// Logical AND NOT.
  | VPANDN = 1210
  /// Logical AND NOT.
  | VPANDND = 1211
  /// Logical AND NOT.
  | VPANDNQ = 1212
  /// Logical AND.
  | VPANDQ = 1213
  /// Average Packed Integers.
  | VPAVGB = 1214
  /// Average Packed Integers.
  | VPAVGW = 1215
  /// Blend Packed Dwords.
  | VPBLENDD = 1216
  /// Blend Byte/Word Vectors Using an Opmask Control.
  | VPBLENDMB = 1217
  /// Blend Int32/Int64 Vectors Using an OpMask Control.
  | VPBLENDMD = 1218
  /// Blend Int32/Int64 Vectors Using an OpMask Control.
  | VPBLENDMQ = 1219
  /// Blend Byte/Word Vectors Using an Opmask Control.
  | VPBLENDMW = 1220
  /// Variable Blend Packed Bytes.
  | VPBLENDVB = 1221
  /// Blend Packed Words.
  | VPBLENDW = 1222
  /// Load With Broadcast Integer Data From General Purpose Register.
  | VPBROADCASTB = 1223
  /// Load Integer and Broadcast.
  | VPBROADCASTD = 1224
  /// VPBROADCASTMB2Q xmm1,k1: Broadcast low byte value in k1 to two locations
  /// in xmm1.
  /// VPBROADCASTMB2Q ymm1,k1: Broadcast low byte value in k1 to four locations
  /// in ymm1.
  /// VPBROADCASTMB2Q zmm1,k1: Broadcast low byte value in k1 to eight locations
  /// in zmm1.
  | VPBROADCASTMB2Q = 1225
  /// VPBROADCASTMW2D xmm1,k1: Broadcast low word value in k1 to four locations
  /// in xmm1.
  /// VPBROADCASTMW2D ymm1,k1: Broadcast low word value in k1 to eight locations
  /// in ymm1.
  /// VPBROADCASTMW2D zmm1,k1: Broadcast low word value in k1 to sixteen
  /// locations in zmm1.
  | VPBROADCASTMW2D = 1226
  /// Load Integer and Broadcast.
  | VPBROADCASTQ = 1227
  /// Load Integer and Broadcast.
  | VPBROADCASTW = 1228
  /// Carry-Less Multiplication Quadword.
  | VPCLMULQDQ = 1229
  /// Compare Packed Byte Values Into Mask.
  | VPCMPB = 1230
  /// Compare Packed Integer Values Into Mask.
  | VPCMPD = 1231
  /// Compare Packed Data for Equal.
  | VPCMPEQB = 1232
  /// Compare Packed Data for Equal.
  | VPCMPEQD = 1233
  /// Compare Packed Qword Data for Equal.
  | VPCMPEQQ = 1234
  /// Compare Packed Data for Equal.
  | VPCMPEQW = 1235
  /// Packed Compare Explicit Length Strings, Return Index.
  | VPCMPESTRI = 1236
  /// Packed Compare Explicit Length Strings, Return Mask.
  | VPCMPESTRM = 1237
  /// Compare Packed Signed Integers for Greater Than.
  | VPCMPGTB = 1238
  /// Compare Packed Signed Integers for Greater Than.
  | VPCMPGTD = 1239
  /// Compare Packed Data for Greater Than.
  | VPCMPGTQ = 1240
  /// Compare Packed Signed Integers for Greater Than.
  | VPCMPGTW = 1241
  /// Packed Compare Implicit Length Strings, Return Index.
  | VPCMPISTRI = 1242
  /// Packed Compare Implicit Length Strings, Return Mask.
  | VPCMPISTRM = 1243
  /// Compare Packed Integer Values Into Mask.
  | VPCMPQ = 1244
  /// Compare Packed Byte Values Into Mask.
  | VPCMPUB = 1245
  /// Compare Packed Integer Values Into Mask.
  | VPCMPUD = 1246
  /// Compare Packed Integer Values Into Mask.
  | VPCMPUQ = 1247
  /// Compare Packed Word Values Into Mask.
  | VPCMPUW = 1248
  /// Compare Packed Word Values Into Mask.
  | VPCMPW = 1249
  /// Store Sparse Packed Byte/Word Integer Values Into Dense Memory/Register.
  | VPCOMPRESSB = 1250
  /// Store Sparse Packed Doubleword Integer Values Into Dense Memory/Register.
  | VPCOMPRESSD = 1251
  /// Store Sparse Packed Quadword Integer Values Into Dense Memory/Register.
  | VPCOMPRESSQ = 1252
  /// VPCOMPRESSW m128{k1},xmm1: Compress up to 128 bits of packed word values
  /// from xmm1 to m128 with writemask k1.
  /// VPCOMPRESSW xmm1{k1}{z},xmm2: Compress up to 128 bits of packed word
  /// values from xmm2 to xmm1 with writemask k1.
  /// VPCOMPRESSW m256{k1},ymm1: Compress up to 256 bits of packed word values
  /// from ymm1 to m256 with writemask k1.
  /// VPCOMPRESSW ymm1{k1}{z},ymm2: Compress up to 256 bits of packed word
  /// values from ymm2 to ymm1 with writemask k1.
  /// VPCOMPRESSW m512{k1},zmm1: Compress up to 512 bits of packed word values
  /// from zmm1 to m512 with writemask k1.
  /// VPCOMPRESSW zmm1{k1}{z},zmm2: Compress up to 512 bits of packed word
  /// values from zmm2 to zmm1 with writemask k1.
  | VPCOMPRESSW = 1253
  /// Detect Conflicts Within a Vector of Packed Dword/Qword Values Into Dense
  /// Memory/ Register.
  | VPCONFLICTD = 1254
  /// VPCONFLICTQ xmm1{k1}{z},xmm2/m128/m64bcst: Detect duplicate quad-word
  /// values in xmm2/m128/m64bcst using writemask k1.
  /// VPCONFLICTQ ymm1{k1}{z},ymm2/m256/m64bcst: Detect duplicate quad-word
  /// values in ymm2/m256/m64bcst using writemask k1.
  /// VPCONFLICTQ zmm1{k1}{z},zmm2/m512/m64bcst: Detect duplicate quad-word
  /// values in zmm2/m512/m64bcst using writemask k1.
  | VPCONFLICTQ = 1255
  /// VPDPBSSD xmm1,xmm2,xmm3/m128: Multiply groups of 4 pairs of signed bytes
  /// in xmm3/m128 with corresponding signed bytes of xmm2, summing those
  /// products and adding them to the doubleword result in xmm1.
  /// VPDPBSSD ymm1,ymm2,ymm3/m256: Multiply groups of 4 pairs of signed bytes
  /// in ymm3/m256 with corresponding signed bytes of ymm2, summing those
  /// products and adding them to the doubleword result in ymm1.
  | VPDPBSSD = 1256
  /// VPDPBSSDS xmm1,xmm2,xmm3/m128: Multiply groups of 4 pairs of signed bytes
  /// in xmm3/m128 with corresponding signed bytes of xmm2, summing those
  /// products and adding them to the doubleword result, with signed saturation
  /// in xmm1.
  /// VPDPBSSDS ymm1,ymm2,ymm3/m256: Multiply groups of 4 pairs of signed bytes
  /// in ymm3/m256 with corresponding signed bytes of ymm2, summing those
  /// products and adding them to the doubleword result, with signed saturation
  /// in ymm1.
  | VPDPBSSDS = 1257
  /// VPDPBSUD xmm1,xmm2,xmm3/m128: Multiply groups of 4 pairs of unsigned bytes
  /// in xmm3/m128 with corresponding signed bytes of xmm2, summing those
  /// products and adding them to doubleword result in xmm1.
  /// VPDPBSUD ymm1,ymm2,ymm3/m256: Multiply groups of 4 pairs of unsigned bytes
  /// in ymm3/m256 with corresponding signed bytes of ymm2, summing those
  /// products and adding them to doubleword result in ymm1.
  | VPDPBSUD = 1258
  /// VPDPBSUDS xmm1,xmm2,xmm3/m128: Multiply groups of 4 pairs of unsigned
  /// bytes in xmm3/m128 with corresponding signed bytes of xmm2, summing those
  /// products and adding them to doubleword result, with signed saturation in
  /// xmm1.
  /// VPDPBSUDS ymm1,ymm2,ymm3/m256: Multiply groups of 4 pairs of unsigned
  /// bytes in ymm3/m256 with corresponding signed bytes of ymm2, summing those
  /// products and adding them to doubleword result, with signed saturation in
  /// ymm1.
  | VPDPBSUDS = 1259
  /// Multiply and Add Unsigned and Signed Bytes.
  | VPDPBUSD = 1260
  /// Multiply and Add Unsigned and Signed Bytes With Saturation.
  | VPDPBUSDS = 1261
  /// VPDPBUUD xmm1,xmm2,xmm3/m128: Multiply groups of 4 pairs of unsigned bytes
  /// in xmm3/m128 with corresponding unsigned bytes of xmm2, summing those
  /// products and adding them to doubleword result in xmm1.
  /// VPDPBUUD ymm1,ymm2,ymm3/m256: Multiply groups of 4 pairs of unsigned bytes
  /// in ymm3/m256 with corresponding unsigned bytes of ymm2, summing those
  /// products and adding them to doubleword result in ymm1.
  | VPDPBUUD = 1262
  /// VPDPBUUDS xmm1,xmm2,xmm3/m128: Multiply groups of 4 pairs of unsigned
  /// bytes in xmm3/m128 with corresponding unsigned bytes of xmm2, summing
  /// those products and adding them to the doubleword result, with unsigned
  /// saturation in xmm1.
  /// VPDPBUUDS ymm1,ymm2,ymm3/m256: Multiply groups of 4 pairs of unsigned
  /// bytes in ymm3/m256 with corresponding unsigned bytes of ymm2, summing
  /// those products and adding them to the doubleword result, with unsigned
  /// saturation in ymm1.
  | VPDPBUUDS = 1263
  /// Multiply and Add Signed Word Integers.
  | VPDPWSSD = 1264
  /// Multiply and Add Signed Word Integers With Saturation.
  | VPDPWSSDS = 1265
  /// VPDPWSUD xmm1,xmm2,xmm3/m128: Multiply groups of 2 pairs of unsigned words
  /// in xmm3/m128 with corresponding signed words of xmm2, summing those
  /// products and adding them to the doubleword result in xmm1.
  /// VPDPWSUD ymm1,ymm2,ymm3/m256: Multiply groups of 2 pairs of unsigned words
  /// in ymm3/m256 with corresponding signed words of ymm2, summing those
  /// products and adding them to the doubleword result in ymm1.
  | VPDPWSUD = 1266
  /// VPDPWSUDS xmm1,xmm2,xmm3/m128: Multiply groups of 2 pairs of unsigned
  /// words in xmm3/m128 with corresponding signed words of xmm2, summing those
  /// products and adding them to the doubleword result, with signed saturation
  /// in xmm1.
  /// VPDPWSUDS ymm1,ymm2,ymm3/m256: Multiply groups of 2 pairs of unsigned
  /// words in ymm3/m256 with corresponding signed words of ymm2, summing those
  /// products and adding them to the doubleword result, with signed saturation
  /// in ymm1.
  | VPDPWSUDS = 1267
  /// VPDPWUSD xmm1,xmm2,xmm3/m128: Multiply groups of 2 pairs of signed words
  /// in xmm3/m128 with corresponding unsigned words of xmm2, summing those
  /// products and adding them to doubleword result in xmm1.
  /// VPDPWUSD ymm1,ymm2,ymm3/m256: Multiply groups of 2 pairs of signed words
  /// in ymm3/m256 with corresponding unsigned words of ymm2, summing those
  /// products and adding them to doubleword result in ymm1.
  | VPDPWUSD = 1268
  /// VPDPWUSDS xmm1,xmm2,xmm3/m128: Multiply groups of 2 pairs of signed words
  /// in xmm3/m128 with corresponding unsigned words of xmm2, summing those
  /// products and adding them to doubleword result, with signed saturation in
  /// xmm1.
  /// VPDPWUSDS ymm1,ymm2,ymm3/m256: Multiply groups of 2 pairs of signed words
  /// in ymm3/m256 with corresponding unsigned words of ymm2, summing those
  /// products and adding them to doubleword result, with signed saturation in
  /// ymm1.
  | VPDPWUSDS = 1269
  /// VPDPWUUD xmm1,xmm2,xmm3/m128: Multiply groups of 2 pairs of unsigned words
  /// in xmm3/m128 with corresponding unsigned words of xmm2, summing those
  /// products and adding them to doubleword result in xmm1.
  /// VPDPWUUD ymm1,ymm2,ymm3/m256: Multiply groups of 2 pairs of unsigned words
  /// in ymm3/m256 with corresponding unsigned words of ymm2, summing those
  /// products and adding them to doubleword result in ymm1.
  | VPDPWUUD = 1270
  /// VPDPWUUDS xmm1,xmm2,xmm3/m128: Multiply groups of 2 pairs of unsigned
  /// words in xmm3/m128 with corresponding unsigned words of xmm2, summing
  /// those products and adding them to the doubleword result, with unsigned
  /// saturation in xmm1.
  /// VPDPWUUDS ymm1,ymm2,ymm3/m256: Multiply groups of 2 pairs of unsigned
  /// words in ymm3/m256 with corresponding unsigned words of ymm2, summing
  /// those products and adding them to the doubleword result, with unsigned
  /// saturation in ymm1.
  | VPDPWUUDS = 1271
  /// Permute Floating-Point Values.
  | VPERM2F128 = 1272
  /// Permute Integer Values.
  | VPERM2I128 = 1273
  /// Permute Packed Bytes Elements.
  | VPERMB = 1274
  /// Permute Packed Doubleword/Word Elements.
  | VPERMD = 1275
  /// Full Permute of Bytes From Two Tables Overwriting the Index.
  | VPERMI2B = 1276
  /// VPERMI2D xmm1{k1}{z},xmm2,xmm3/m128/m32bcst: Permute double-words from two
  /// tables in xmm3/m128/m32bcst and xmm2 using indexes in xmm1 and store the
  /// result in xmm1 using writemask k1.
  /// VPERMI2D ymm1{k1}{z},ymm2,ymm3/m256/m32bcst: Permute double-words from two
  /// tables in ymm3/m256/m32bcst and ymm2 using indexes in ymm1 and store the
  /// result in ymm1 using writemask k1.
  /// VPERMI2D zmm1{k1}{z},zmm2,zmm3/m512/m32bcst: Permute double-words from two
  /// tables in zmm3/m512/m32bcst and zmm2 using indices in zmm1 and store the
  /// result in zmm1 using writemask k1.
  | VPERMI2D = 1277
  /// VPERMI2PD xmm1{k1}{z},xmm2,xmm3/m128/m64bcst: Permute double precision
  /// floating-point values from two tables in xmm3/m128/m64bcst and xmm2 using
  /// indexes in xmm1 and store the result in xmm1 using writemask k1.
  /// VPERMI2PD ymm1{k1}{z},ymm2,ymm3/m256/m64bcst: Permute double precision
  /// floating-point values from two tables in ymm3/m256/m64bcst and ymm2 using
  /// indexes in ymm1 and store the result in ymm1 using writemask k1.
  /// VPERMI2PD zmm1{k1}{z},zmm2,zmm3/m512/m64bcst: Permute double precision
  /// floating-point values from two tables in zmm3/m512/m64bcst and zmm2 using
  /// indices in zmm1 and store the result in zmm1 using writemask k1.
  | VPERMI2PD = 1278
  /// VPERMI2PS xmm1{k1}{z},xmm2,xmm3/m128/m32bcst: Permute single-precision
  /// floating-point values from two tables in xmm3/m128/m32bcst and xmm2 using
  /// indexes in xmm1 and store the result in xmm1 using writemask k1.
  /// VPERMI2PS ymm1{k1}{z},ymm2,ymm3/m256/m32bcst: Permute single-precision
  /// floating-point values from two tables in ymm3/m256/m32bcst and ymm2 using
  /// indexes in ymm1 and store the result in ymm1 using writemask k1.
  /// VPERMI2PS zmm1{k1}{z},zmm2,zmm3/m512/m32bcst: Permute single-precision
  /// floating-point values from two tables in zmm3/m512/m32bcst and zmm2 using
  /// indices in zmm1 and store the result in zmm1 using writemask k1.
  | VPERMI2PS = 1279
  /// VPERMI2Q xmm1{k1}{z},xmm2,xmm3/m128/m64bcst: Permute quad-words from two
  /// tables in xmm3/m128/m64bcst and xmm2 using indexes in xmm1 and store the
  /// result in xmm1 using writemask k1.
  /// VPERMI2Q ymm1{k1}{z},ymm2,ymm3/m256/m64bcst: Permute quad-words from two
  /// tables in ymm3/m256/m64bcst and ymm2 using indexes in ymm1 and store the
  /// result in ymm1 using writemask k1.
  /// VPERMI2Q zmm1{k1}{z},zmm2,zmm3/m512/m64bcst: Permute quad-words from two
  /// tables in zmm3/m512/m64bcst and zmm2 using indices in zmm1 and store the
  /// result in zmm1 using writemask k1.
  | VPERMI2Q = 1280
  /// Full Permute From Two Tables Overwriting the Index.
  | VPERMI2W = 1281
  /// Permute In-Lane of Pairs of Double Precision Floating-Point Values.
  | VPERMILPD = 1282
  /// Permute In-Lane of Quadruples of Single Precision Floating-Point Values.
  | VPERMILPS = 1283
  /// Permute Double Precision Floating-Point Elements.
  | VPERMPD = 1284
  /// Permute Single Precision Floating-Point Elements.
  | VPERMPS = 1285
  /// Qwords Element Permutation.
  | VPERMQ = 1286
  /// Full Permute of Bytes From Two Tables Overwriting a Table.
  | VPERMT2B = 1287
  /// VPERMT2D xmm1{k1}{z},xmm2,xmm3/m128/m32bcst: Permute double-words from two
  /// tables in xmm3/m128/m32bcst and xmm1 using indexes in xmm2 and store the
  /// result in xmm1 using writemask k1.
  /// VPERMT2D ymm1{k1}{z},ymm2,ymm3/m256/m32bcst: Permute double-words from two
  /// tables in ymm3/m256/m32bcst and ymm1 using indexes in ymm2 and store the
  /// result in ymm1 using writemask k1.
  /// VPERMT2D zmm1{k1}{z},zmm2,zmm3/m512/m32bcst: Permute double-words from two
  /// tables in zmm3/m512/m32bcst and zmm1 using indices in zmm2 and store the
  /// result in zmm1 using writemask k1.
  | VPERMT2D = 1288
  /// VPERMT2PD xmm1{k1}{z},xmm2,xmm3/m128/m64bcst: Permute double precision
  /// floating-point values from two tables in xmm3/m128/m64bcst and xmm1 using
  /// indexes in xmm2 and store the result in xmm1 using writemask k1.
  /// VPERMT2PD ymm1{k1}{z},ymm2,ymm3/m256/m64bcst: Permute double precision
  /// floating-point values from two tables in ymm3/m256/m64bcst and ymm1 using
  /// indexes in ymm2 and store the result in ymm1 using writemask k1.
  /// VPERMT2PD zmm1{k1}{z},zmm2,zmm3/m512/m64bcst: Permute double precision
  /// floating-point values from two tables in zmm3/m512/m64bcst and zmm1 using
  /// indices in zmm2 and store the result in zmm1 using writemask k1.
  | VPERMT2PD = 1289
  /// VPERMT2PS xmm1{k1}{z},xmm2,xmm3/m128/m32bcst: Permute single-precision
  /// floating-point values from two tables in xmm3/m128/m32bcst and xmm1 using
  /// indexes in xmm2 and store the result in xmm1 using writemask k1.
  /// VPERMT2PS ymm1{k1}{z},ymm2,ymm3/m256/m32bcst: Permute single-precision
  /// floating-point values from two tables in ymm3/m256/m32bcst and ymm1 using
  /// indexes in ymm2 and store the result in ymm1 using writemask k1.
  /// VPERMT2PS zmm1{k1}{z},zmm2,zmm3/m512/m32bcst: Permute single-precision
  /// floating-point values from two tables in zmm3/m512/m32bcst and zmm1 using
  /// indices in zmm2 and store the result in zmm1 using writemask k1.
  | VPERMT2PS = 1290
  /// VPERMT2Q xmm1{k1}{z},xmm2,xmm3/m128/m64bcst: Permute quad-words from two
  /// tables in xmm3/m128/m64bcst and xmm1 using indexes in xmm2 and store the
  /// result in xmm1 using writemask k1.
  /// VPERMT2Q ymm1{k1}{z},ymm2,ymm3/m256/m64bcst: Permute quad-words from two
  /// tables in ymm3/m256/m64bcst and ymm1 using indexes in ymm2 and store the
  /// result in ymm1 using writemask k1.
  /// VPERMT2Q zmm1{k1}{z},zmm2,zmm3/m512/m64bcst: Permute quad-words from two
  /// tables in zmm3/m512/m64bcst and zmm1 using indices in zmm2 and store the
  /// result in zmm1 using writemask k1.
  | VPERMT2Q = 1291
  /// Full Permute From Two Tables Overwriting One Table.
  | VPERMT2W = 1292
  /// Permute Packed Doubleword/Word Elements.
  | VPERMW = 1293
  /// Expand Byte/Word Values.
  | VPEXPANDB = 1294
  /// Load Sparse Packed Doubleword Integer Values From Dense Memory/Register.
  | VPEXPANDD = 1295
  /// Load Sparse Packed Quadword Integer Values From Dense Memory/Register.
  | VPEXPANDQ = 1296
  /// Expand Byte/Word Values.
  | VPEXPANDW = 1297
  /// Extract Byte/Dword/Qword.
  | VPEXTRB = 1298
  /// Extract Byte/Dword/Qword.
  | VPEXTRD = 1299
  /// Extract Byte/Dword/Qword.
  | VPEXTRQ = 1300
  /// Extract Word.
  | VPEXTRW = 1301
  /// Gather Packed Dword, Packed Qword With Signed Dword Indices.
  | VPGATHERDD = 1302
  /// Gather Packed Qword Values Using Signed Dword/Qword Indices.
  | VPGATHERDQ = 1303
  /// Gather Packed Dword, Packed Qword with Signed Qword Indices.
  | VPGATHERQD = 1304
  /// Gather Packed Qword Values Using Signed Dword/Qword Indices.
  | VPGATHERQQ = 1305
  /// Packed Horizontal Add.
  | VPHADDD = 1306
  /// Packed Horizontal Add and Saturate.
  | VPHADDSW = 1307
  /// Packed Horizontal Add.
  | VPHADDW = 1308
  /// Packed Horizontal Word Minimum.
  | VPHMINPOSUW = 1309
  /// Packed Horizontal Subtract.
  | VPHSUBD = 1310
  /// Packed Horizontal Subtract and Saturate.
  | VPHSUBSW = 1311
  /// Packed Horizontal Subtract.
  | VPHSUBW = 1312
  /// Insert Byte/Dword/Qword.
  | VPINSRB = 1313
  /// Insert Byte/Dword/Qword.
  | VPINSRD = 1314
  /// Insert Byte/Dword/Qword.
  | VPINSRQ = 1315
  /// Insert Word.
  | VPINSRW = 1316
  /// Count the Number of Leading Zero Bits for Packed Dword, Packed Qword
  /// Values.
  | VPLZCNTD = 1317
  /// VPLZCNTQ xmm1{k1}{z},xmm2/m128/m64bcst: Count the number of leading zero
  /// bits in each qword element of xmm2/m128/m64bcst using writemask k1.
  /// VPLZCNTQ ymm1{k1}{z},ymm2/m256/m64bcst: Count the number of leading zero
  /// bits in each qword element of ymm2/m256/m64bcst using writemask k1.
  /// VPLZCNTQ zmm1{k1}{z},zmm2/m512/m64bcst: Count the number of leading zero
  /// bits in each qword element of zmm2/m512/m64bcst using writemask k1.
  | VPLZCNTQ = 1318
  /// Packed Multiply of Unsigned 52-Bit Unsigned Integers and Add High 52-Bit
  /// Products to 64-Bit Accumulators.
  | VPMADD52HUQ = 1319
  /// Packed Multiply of Unsigned 52-Bit Integers and Add the Low 52-Bit
  /// Products to Qword Accumulators.
  | VPMADD52LUQ = 1320
  /// Multiply and Add Packed Signed and Unsigned Bytes.
  | VPMADDUBSW = 1321
  /// Multiply and Add Packed Integers.
  | VPMADDWD = 1322
  /// Conditional SIMD Integer Packed Loads and Stores.
  | VPMASKMOVD = 1323
  /// Conditional SIMD Integer Packed Loads and Stores.
  | VPMASKMOVQ = 1324
  /// Maximum of Packed Signed Integers.
  | VPMAXSB = 1325
  /// Maximum of Packed Signed Integers.
  | VPMAXSD = 1326
  /// Maximum of Packed Signed Integers.
  | VPMAXSQ = 1327
  /// Maximum of Packed Signed Integers.
  | VPMAXSW = 1328
  /// Maximum of Packed Unsigned Integers.
  | VPMAXUB = 1329
  /// Maximum of Packed Unsigned Integers.
  | VPMAXUD = 1330
  /// Maximum of Packed Unsigned Integers.
  | VPMAXUQ = 1331
  /// Maximum of Packed Unsigned Integers.
  | VPMAXUW = 1332
  /// Minimum of Packed Signed Integers.
  | VPMINSB = 1333
  /// Minimum of Packed Signed Integers.
  | VPMINSD = 1334
  /// Minimum of Packed Signed Integers.
  | VPMINSQ = 1335
  /// Minimum of Packed Signed Integers.
  | VPMINSW = 1336
  /// Minimum of Packed Unsigned Integers.
  | VPMINUB = 1337
  /// Minimum of Packed Unsigned Integers.
  | VPMINUD = 1338
  /// Minimum of Packed Unsigned Integers.
  | VPMINUQ = 1339
  /// Minimum of Packed Unsigned Integers.
  | VPMINUW = 1340
  /// Convert a Vector Register to a Mask.
  | VPMOVB2M = 1341
  /// Convert a Vector Register to a Mask.
  | VPMOVD2M = 1342
  /// Down Convert DWord to Byte.
  | VPMOVDB = 1343
  /// Down Convert DWord to Word.
  | VPMOVDW = 1344
  /// Convert a Mask Register to a Vector Register.
  | VPMOVM2B = 1345
  /// Convert a Mask Register to a Vector Register.
  | VPMOVM2D = 1346
  /// Convert a Mask Register to a Vector Register.
  | VPMOVM2Q = 1347
  /// Convert a Mask Register to a Vector Register.
  | VPMOVM2W = 1348
  /// Move Byte Mask.
  | VPMOVMSKB = 1349
  /// Convert a Vector Register to a Mask.
  | VPMOVQ2M = 1350
  /// Down Convert QWord to Byte.
  | VPMOVQB = 1351
  /// Down Convert QWord to DWord.
  | VPMOVQD = 1352
  /// Down Convert QWord to Word.
  | VPMOVQW = 1353
  /// Down Convert DWord to Byte.
  | VPMOVSDB = 1354
  /// Down Convert DWord to Word.
  | VPMOVSDW = 1355
  /// Down Convert QWord to Byte.
  | VPMOVSQB = 1356
  /// Down Convert QWord to DWord.
  | VPMOVSQD = 1357
  /// Down Convert QWord to Word.
  | VPMOVSQW = 1358
  /// Down Convert Word to Byte.
  | VPMOVSWB = 1359
  /// Packed Move Sign Extend - Byte to Dword.
  | VPMOVSXBD = 1360
  /// Packed Move Sign Extend - Byte to Qword.
  | VPMOVSXBQ = 1361
  /// Packed Move Sign Extend - Byte to Word.
  | VPMOVSXBW = 1362
  /// Packed Move Sign Extend - Dword to Qword.
  | VPMOVSXDQ = 1363
  /// Packed Move Sign Extend - Word to Dword.
  | VPMOVSXWD = 1364
  /// Packed Move Sign Extend - Word to Qword.
  | VPMOVSXWQ = 1365
  /// Down Convert DWord to Byte.
  | VPMOVUSDB = 1366
  /// Down Convert DWord to Word.
  | VPMOVUSDW = 1367
  /// Down Convert QWord to Byte.
  | VPMOVUSQB = 1368
  /// Down Convert QWord to DWord.
  | VPMOVUSQD = 1369
  /// Down Convert QWord to Word.
  | VPMOVUSQW = 1370
  /// Down Convert Word to Byte.
  | VPMOVUSWB = 1371
  /// Convert a Vector Register to a Mask.
  | VPMOVW2M = 1372
  /// Down Convert Word to Byte.
  | VPMOVWB = 1373
  /// Packed Move Zero Extend - Byte to Dword.
  | VPMOVZXBD = 1374
  /// Packed Move Zero Extend - Byte to Qword.
  | VPMOVZXBQ = 1375
  /// Packed Move Zero Extend - Byte to Word.
  | VPMOVZXBW = 1376
  /// Packed Move Zero Extend - Dword to Qword.
  | VPMOVZXDQ = 1377
  /// Packed Move Zero Extend - Word to Dword.
  | VPMOVZXWD = 1378
  /// Packed Move Zero Extend - Word to Qword.
  | VPMOVZXWQ = 1379
  /// Multiply Packed Doubleword Integers.
  | VPMULDQ = 1380
  /// Packed Multiply High With Round and Scale.
  | VPMULHRSW = 1381
  /// Multiply Packed Unsigned Integers and Store High Result.
  | VPMULHUW = 1382
  /// Multiply Packed Signed Integers and Store High Result.
  | VPMULHW = 1383
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLD = 1384
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLQ = 1385
  /// Multiply Packed Signed Integers and Store Low Result.
  | VPMULLW = 1386
  /// Select Packed Unaligned Bytes From Quadword Sources.
  | VPMULTISHIFTQB = 1387
  /// Multiply Packed Unsigned Doubleword Integers.
  | VPMULUDQ = 1388
  /// Return the Count of Number of Bits Set to 1.
  | VPOPCNTB = 1389
  /// Return the Count of Number of Bits Set to 1.
  | VPOPCNTD = 1390
  /// Return the Count of Number of Bits Set to 1.
  | VPOPCNTQ = 1391
  /// Return the Count of Number of Bits Set to 1.
  | VPOPCNTW = 1392
  /// Bitwise Logical OR.
  | VPOR = 1393
  /// Bitwise Logical OR.
  | VPORD = 1394
  /// Bitwise Logical OR.
  | VPORQ = 1395
  /// Bit Rotate Left.
  | VPROLD = 1396
  /// Bit Rotate Left.
  | VPROLQ = 1397
  /// Bit Rotate Left.
  | VPROLVD = 1398
  /// Bit Rotate Left.
  | VPROLVQ = 1399
  /// Bit Rotate Right.
  | VPRORD = 1400
  /// Bit Rotate Right.
  | VPRORQ = 1401
  /// Bit Rotate Right.
  | VPRORVD = 1402
  /// Bit Rotate Right.
  | VPRORVQ = 1403
  /// Compute Sum of Absolute Differences.
  | VPSADBW = 1404
  /// Scatter Packed Dword, Packed Qword with Signed Dword, Signed Qword
  /// Indices.
  | VPSCATTERDD = 1405
  /// Scatter Packed Dword, Packed Qword with Signed Dword, Signed Qword
  /// Indices.
  | VPSCATTERDQ = 1406
  /// Scatter Packed Dword, Packed Qword with Signed Dword, Signed Qword
  /// Indices.
  | VPSCATTERQD = 1407
  /// Scatter Packed Dword, Packed Qword with Signed Dword, Signed Qword
  /// Indices.
  | VPSCATTERQQ = 1408
  /// Concatenate and Shift Packed Data Left Logical.
  | VPSHLDD = 1409
  /// Concatenate and Shift Packed Data Left Logical.
  | VPSHLDQ = 1410
  /// Concatenate and Variable Shift Packed Data Left Logical.
  | VPSHLDVD = 1411
  /// Concatenate and Variable Shift Packed Data Left Logical.
  | VPSHLDVQ = 1412
  /// Concatenate and Variable Shift Packed Data Left Logical.
  | VPSHLDVW = 1413
  /// Concatenate and Shift Packed Data Left Logical.
  | VPSHLDW = 1414
  /// Concatenate and Shift Packed Data Right Logical.
  | VPSHRDD = 1415
  /// Concatenate and Shift Packed Data Right Logical.
  | VPSHRDQ = 1416
  /// Concatenate and Variable Shift Packed Data Right Logical.
  | VPSHRDVD = 1417
  /// Concatenate and Variable Shift Packed Data Right Logical.
  | VPSHRDVQ = 1418
  /// Concatenate and Variable Shift Packed Data Right Logical.
  | VPSHRDVW = 1419
  /// Concatenate and Shift Packed Data Right Logical.
  | VPSHRDW = 1420
  /// Packed Shuffle Bytes.
  | VPSHUFB = 1421
  /// Shuffle Bits From Quadword Elements Using Byte Indexes Into Mask.
  | VPSHUFBITQMB = 1422
  /// Shuffle Packed Doublewords.
  | VPSHUFD = 1423
  /// Shuffle Packed High Words.
  | VPSHUFHW = 1424
  /// Shuffle Packed Low Words.
  | VPSHUFLW = 1425
  /// Packed SIGN.
  | VPSIGNB = 1426
  /// Packed SIGN.
  | VPSIGND = 1427
  /// Packed SIGN.
  | VPSIGNW = 1428
  /// Shift Packed Data Left Logical.
  | VPSLLD = 1429
  /// Shift Double Quadword Left Logical.
  | VPSLLDQ = 1430
  /// Shift Packed Data Left Logical.
  | VPSLLQ = 1431
  /// Variable Bit Shift Left Logical.
  | VPSLLVD = 1432
  /// Variable Bit Shift Left Logical.
  | VPSLLVQ = 1433
  /// Variable Bit Shift Left Logical.
  | VPSLLVW = 1434
  /// Shift Packed Data Left Logical.
  | VPSLLW = 1435
  /// Shift Packed Data Right Arithmetic.
  | VPSRAD = 1436
  /// Shift Packed Data Right Arithmetic.
  | VPSRAQ = 1437
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVD = 1438
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVQ = 1439
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVW = 1440
  /// Shift Packed Data Right Arithmetic.
  | VPSRAW = 1441
  /// Shift Packed Data Right Logical.
  | VPSRLD = 1442
  /// Shift Double Quadword Right Logical.
  | VPSRLDQ = 1443
  /// Shift Packed Data Right Logical.
  | VPSRLQ = 1444
  /// Variable Bit Shift Right Logical.
  | VPSRLVD = 1445
  /// Variable Bit Shift Right Logical.
  | VPSRLVQ = 1446
  /// Variable Bit Shift Right Logical.
  | VPSRLVW = 1447
  /// Shift Packed Data Right Logical.
  | VPSRLW = 1448
  /// Subtract Packed Integers.
  | VPSUBB = 1449
  /// Subtract Packed Integers.
  | VPSUBD = 1450
  /// Subtract Packed Quadword Integers.
  | VPSUBQ = 1451
  /// Subtract Packed Signed Integers With Signed Saturation.
  | VPSUBSB = 1452
  /// Subtract Packed Signed Integers With Signed Saturation.
  | VPSUBSW = 1453
  /// Subtract Packed Unsigned Integers With Unsigned Saturation.
  | VPSUBUSB = 1454
  /// Subtract Packed Unsigned Integers With Unsigned Saturation.
  | VPSUBUSW = 1455
  /// Subtract Packed Integers.
  | VPSUBW = 1456
  /// Bitwise Ternary Logic.
  | VPTERNLOGD = 1457
  /// Bitwise Ternary Logic.
  | VPTERNLOGQ = 1458
  /// Logical Compare.
  | VPTEST = 1459
  /// Logical AND and Set Mask.
  | VPTESTMB = 1460
  /// Logical AND and Set Mask.
  | VPTESTMD = 1461
  /// Logical AND and Set Mask.
  | VPTESTMQ = 1462
  /// Logical AND and Set Mask.
  | VPTESTMW = 1463
  /// Logical NAND and Set.
  | VPTESTNMB = 1464
  /// VPTESTNMD k2{k1},xmm2,xmm3/m128/m32bcst: Bitwise NAND of packed doubleword
  /// integers in xmm2 and xmm3/m128/m32bcst and set mask k2 to reflect the
  /// zero/non-zero status of each element of the result, under writemask k1.
  /// VPTESTNMD k2{k1},ymm2,ymm3/m256/m32bcst: Bitwise NAND of packed doubleword
  /// integers in ymm2 and ymm3/m256/m32bcst and set mask k2 to reflect the
  /// zero/non-zero status of each element of the result, under writemask k1.
  /// VPTESTNMD k2{k1},zmm2,zmm3/m512/m32bcst: Bitwise NAND of packed doubleword
  /// integers in zmm2 and zmm3/m512/m32bcst and set mask k2 to reflect the
  /// zero/non-zero status of each element of the result, under writemask k1.
  | VPTESTNMD = 1465
  /// VPTESTNMQ k2{k1},xmm2,xmm3/m128/m64bcst: Bitwise NAND of packed quadword
  /// integers in xmm2 and xmm3/m128/m64bcst and set mask k2 to reflect the
  /// zero/non-zero status of each element of the result, under writemask k1.
  /// VPTESTNMQ k2{k1},ymm2,ymm3/m256/m64bcst: Bitwise NAND of packed quadword
  /// integers in ymm2 and ymm3/m256/m64bcst and set mask k2 to reflect the
  /// zero/non-zero status of each element of the result, under writemask k1.
  /// VPTESTNMQ k2{k1},zmm2,zmm3/m512/m64bcst: Bitwise NAND of packed quadword
  /// integers in zmm2 and zmm3/m512/m64bcst and set mask k2 to reflect the
  /// zero/non-zero status of each element of the result, under writemask k1.
  | VPTESTNMQ = 1466
  /// VPTESTNMW k2{k1},xmm2,xmm3/m128: Bitwise NAND of packed word integers in
  /// xmm2 and xmm3/m128 and set mask k2 to reflect the zero/non- zero status of
  /// each element of the result, under writemask k1.
  /// VPTESTNMW k2{k1},ymm2,ymm3/m256: Bitwise NAND of packed word integers in
  /// ymm2 and ymm3/m256 and set mask k2 to reflect the zero/non- zero status of
  /// each element of the result, under writemask k1.
  /// VPTESTNMW k2{k1},zmm2,zmm3/m512: Bitwise NAND of packed word integers in
  /// zmm2 and zmm3/m512 and set mask k2 to reflect the zero/non- zero status of
  /// each element of the result, under writemask k1.
  | VPTESTNMW = 1467
  /// Unpack High Data.
  | VPUNPCKHBW = 1468
  /// Unpack High Data.
  | VPUNPCKHDQ = 1469
  /// Unpack High Data.
  | VPUNPCKHQDQ = 1470
  /// Unpack High Data.
  | VPUNPCKHWD = 1471
  /// Unpack Low Data.
  | VPUNPCKLBW = 1472
  /// Unpack Low Data.
  | VPUNPCKLDQ = 1473
  /// Unpack Low Data.
  | VPUNPCKLQDQ = 1474
  /// Unpack Low Data.
  | VPUNPCKLWD = 1475
  /// Logical Exclusive OR.
  | VPXOR = 1476
  /// Logical Exclusive OR.
  | VPXORD = 1477
  /// Logical Exclusive OR.
  | VPXORQ = 1478
  /// Range Restriction Calculation for Packed Pairs of Float64 Values.
  | VRANGEPD = 1479
  /// Range Restriction Calculation for Packed Pairs of Float32 Values.
  | VRANGEPS = 1480
  /// Range Restriction Calculation From a Pair of Scalar Float64 Values.
  | VRANGESD = 1481
  /// Range Restriction Calculation From a Pair of Scalar Float32 Values.
  | VRANGESS = 1482
  /// Compute Approximate Reciprocals of Packed Float64 Values.
  | VRCP14PD = 1483
  /// Compute Approximate Reciprocals of Packed Float32 Values.
  | VRCP14PS = 1484
  /// Compute Approximate Reciprocal of Scalar Float64 Value.
  | VRCP14SD = 1485
  /// Compute Approximate Reciprocal of Scalar Float32 Value.
  | VRCP14SS = 1486
  /// Approximation to the Reciprocal of Packed Double Precision Floating-Point
  /// Values With Less Than 2^-28 Relative Error.
  | VRCP28PD = 1487
  /// Approximation to the Reciprocal of Packed Single Precision Floating-Point
  /// Values With Less Than 2^-28 Relative Error.
  | VRCP28PS = 1488
  /// Approximation to the Reciprocal of Scalar Double Precision Floating-Point
  /// Value With Less Than 2^-28 Relative Error.
  | VRCP28SD = 1489
  /// Approximation to the Reciprocal of Scalar Single Precision Floating-Point
  /// Value With Less Than 2^-28 Relative Error.
  | VRCP28SS = 1490
  /// Compute Reciprocals of Packed FP16 Values.
  | VRCPPH = 1491
  /// Compute Reciprocals of Packed Single Precision Floating-Point Values.
  | VRCPPS = 1492
  /// Compute Reciprocal of Scalar FP16 Value.
  | VRCPSH = 1493
  /// Compute Reciprocal of Scalar Single Precision Floating-Point Values.
  | VRCPSS = 1494
  /// Perform Reduction Transformation on Packed Float64 Values.
  | VREDUCEPD = 1495
  /// Perform Reduction Transformation on Packed FP16 Values.
  | VREDUCEPH = 1496
  /// Perform Reduction Transformation on Packed Float32 Values.
  | VREDUCEPS = 1497
  /// Perform a Reduction Transformation on a Scalar Float64 Value.
  | VREDUCESD = 1498
  /// Perform Reduction Transformation on Scalar FP16 Value.
  | VREDUCESH = 1499
  /// Perform a Reduction Transformation on a Scalar Float32 Value.
  | VREDUCESS = 1500
  /// Round Packed Float64 Values to Include a Given Number of Fraction Bits.
  | VRNDSCALEPD = 1501
  /// Round Packed FP16 Values to Include a Given Number of Fraction Bits.
  | VRNDSCALEPH = 1502
  /// Round Packed Float32 Values to Include a Given Number of Fraction Bits.
  | VRNDSCALEPS = 1503
  /// Round Scalar Float64 Value to Include a Given Number of Fraction Bits.
  | VRNDSCALESD = 1504
  /// Round Scalar FP16 Value to Include a Given Number of Fraction Bits.
  | VRNDSCALESH = 1505
  /// Round Scalar Float32 Value to Include a Given Number of Fraction Bits.
  | VRNDSCALESS = 1506
  /// Round Packed Double Precision Floating-Point Values.
  | VROUNDPD = 1507
  /// Round Packed Single Precision Floating-Point Values.
  | VROUNDPS = 1508
  /// Round Scalar Double Precision Floating-Point Values.
  | VROUNDSD = 1509
  /// Round Scalar Single Precision Floating-Point Values.
  | VROUNDSS = 1510
  /// Compute Approximate Reciprocals of Square Roots of Packed Float64 Values.
  | VRSQRT14PD = 1511
  /// Compute Approximate Reciprocals of Square Roots of Packed Float32 Values.
  | VRSQRT14PS = 1512
  /// Compute Approximate Reciprocal of Square Root of Scalar Float64 Value.
  | VRSQRT14SD = 1513
  /// Compute Approximate Reciprocal of Square Root of Scalar Float32 Value.
  | VRSQRT14SS = 1514
  /// Approximation to the Reciprocal Square Root of Packed Double Precision
  /// Floating-Point Values With Less Than 2^-28.
  | VRSQRT28PD = 1515
  /// Approximation to the Reciprocal Square Root of Packed Single Precision
  /// Floating-Point Values With Less Than 2^-28.
  | VRSQRT28PS = 1516
  /// Approximation to the Reciprocal Square Root of Scalar Double Precision
  /// Floating-Point Value With Less Than 2^-28.
  | VRSQRT28SD = 1517
  /// Approximation to the Reciprocal Square Root of Scalar Single Precision
  /// Floating-Point Value With Less Than 2^-28 Rel-.
  | VRSQRT28SS = 1518
  /// Compute Reciprocals of Square Roots of Packed FP16 Values.
  | VRSQRTPH = 1519
  /// Compute Reciprocals of Square Roots of Packed Single Precision
  /// Floating-Point Values.
  | VRSQRTPS = 1520
  /// Compute Approximate Reciprocal of Square Root of Scalar FP16 Value.
  | VRSQRTSH = 1521
  /// Compute Reciprocal of Square Root of Scalar Single Precision
  /// Floating-Point Value.
  | VRSQRTSS = 1522
  /// Scale Packed Float64 Values With Float64 Values.
  | VSCALEFPD = 1523
  /// Scale Packed FP16 Values with FP16 Values.
  | VSCALEFPH = 1524
  /// Scale Packed Float32 Values With Float32 Values.
  | VSCALEFPS = 1525
  /// Scale Scalar Float64 Values With Float64 Values.
  | VSCALEFSD = 1526
  /// Scale Scalar FP16 Values with FP16 Values.
  | VSCALEFSH = 1527
  /// Scale Scalar Float32 Value With Float32 Value.
  | VSCALEFSS = 1528
  /// Scatter Packed Single Precision, Packed Double Precision Floating-Point
  /// Values with Signed Dword and Qword Indices.
  | VSCATTERDPD = 1529
  /// Scatter Packed Single Precision, Packed Double Precision Floating-Point
  /// Values with Signed Dword and Qword Indices.
  | VSCATTERDPS = 1530
  /// Sparse Prefetch Packed SP/DP Data Values with.
  | VSCATTERPF0DPD = 1531
  /// Sparse Prefetch Packed SP/DP Data Values with.
  | VSCATTERPF0DPS = 1532
  /// Sparse Prefetch Packed SP/DP Data Values with.
  | VSCATTERPF0QPD = 1533
  /// Sparse Prefetch Packed SP/DP Data Values with.
  | VSCATTERPF0QPS = 1534
  /// Sparse Prefetch Packed SP/DP Data Values With.
  | VSCATTERPF1DPD = 1535
  /// Sparse Prefetch Packed SP/DP Data Values With.
  | VSCATTERPF1DPS = 1536
  /// Sparse Prefetch Packed SP/DP Data Values With.
  | VSCATTERPF1QPD = 1537
  /// Sparse Prefetch Packed SP/DP Data Values With.
  | VSCATTERPF1QPS = 1538
  /// Scatter Packed Single Precision, Packed Double Precision Floating-Point
  /// Values with Signed Dword and Qword Indices.
  | VSCATTERQPD = 1539
  /// Scatter Packed Single Precision, Packed Double Precision Floating-Point
  /// Values with Signed Dword and Qword Indices.
  | VSCATTERQPS = 1540
  /// Perform an Intermediate Calculation for the Next Four SHA512 Message
  /// Qwords.
  | VSHA512MSG1 = 1541
  /// Perform a Final Calculation for the Next Four SHA512 Message Qwords.
  | VSHA512MSG2 = 1542
  /// Perform Two Rounds of SHA512 Operation.
  | VSHA512RNDS2 = 1543
  /// VSHUFF32X4 ymm1{k1}{z},ymm2,ymm3/m256/m32bcst,imm8: Shuffle 128-bit packed
  /// single-precision floating- point values selected by imm8 from ymm2 and
  /// ymm3/m256/m32bcst and place results in ymm1 subject to writemask k1.
  /// VSHUFF32x4 zmm1{k1}{z},zmm2,zmm3/m512/m32bcst,imm8: Shuffle 128-bit packed
  /// single-precision floating- point values selected by imm8 from zmm2 and
  /// zmm3/m512/m32bcst and place results in zmm1 subject to writemask k1.
  | VSHUFF32X4 = 1544
  /// VSHUFF64X2 ymm1{k1}{z},ymm2,ymm3/m256/m64bcst,imm8: Shuffle 128-bit packed
  /// double precision floating- point values selected by imm8 from ymm2 and
  /// ymm3/m256/m64bcst and place results in ymm1 subject to writemask k1.
  /// VSHUFF64x2 zmm1{k1}{z},zmm2,zmm3/m512/m64bcst,imm8: Shuffle 128-bit packed
  /// double precision floating- point values selected by imm8 from zmm2 and
  /// zmm3/m512/m64bcst and place results in zmm1 subject to writemask k1.
  | VSHUFF64X2 = 1545
  /// VSHUFI32X4 ymm1{k1}{z},ymm2,ymm3/m256/m32bcst,imm8: Shuffle 128-bit packed
  /// double-word values selected by imm8 from ymm2 and ymm3/m256/m32bcst and
  /// place results in ymm1 subject to writemask k1.
  /// VSHUFI32x4 zmm1{k1}{z},zmm2,zmm3/m512/m32bcst,imm8: Shuffle 128-bit packed
  /// double-word values selected by imm8 from zmm2 and zmm3/m512/m32bcst and
  /// place results in zmm1 subject to writemask k1.
  | VSHUFI32X4 = 1546
  /// VSHUFI64X2 ymm1{k1}{z},ymm2,ymm3/m256/m64bcst,imm8: Shuffle 128-bit packed
  /// quad-word values selected by imm8 from ymm2 and ymm3/m256/m64bcst and
  /// place results in ymm1 subject to writemask k1.
  /// VSHUFI64x2 zmm1{k1}{z},zmm2,zmm3/m512/m64bcst,imm8: Shuffle 128-bit packed
  /// quad-word values selected by imm8 from zmm2 and zmm3/m512/m64bcst and
  /// place results in zmm1 subject to writemask k1.
  | VSHUFI64X2 = 1547
  /// Packed Interleave Shuffle of Pairs of Double Precision Floating-Point
  /// Values.
  | VSHUFPD = 1548
  /// Packed Interleave Shuffle of Quadruplets of Single Precision
  /// Floating-Point Values.
  | VSHUFPS = 1549
  /// Perform Initial Calculation for the Next Four SM3 Message Words.
  | VSM3MSG1 = 1550
  /// Perform Final Calculation for the Next Four SM3 Message Words.
  | VSM3MSG2 = 1551
  /// Perform Two Rounds of SM3 Operation.
  | VSM3RNDS2 = 1552
  /// Perform Four Rounds of SM4 Key Expansion.
  | VSM4KEY4 = 1553
  /// Performs Four Rounds of SM4 Encryption.
  | VSM4RNDS4 = 1554
  /// Square Root of Double Precision Floating-Point Values.
  | VSQRTPD = 1555
  /// Compute Square Root of Packed FP16 Values.
  | VSQRTPH = 1556
  /// Square Root of Single Precision Floating-Point Values.
  | VSQRTPS = 1557
  /// Compute Square Root of Scalar Double Precision Floating-Point Value.
  | VSQRTSD = 1558
  /// Compute Square Root of Scalar FP16 Value.
  | VSQRTSH = 1559
  /// Compute Square Root of Scalar Single Precision Value.
  | VSQRTSS = 1560
  /// Store MXCSR Register State.
  | VSTMXCSR = 1561
  /// Subtract Packed Double Precision Floating-Point Values.
  | VSUBPD = 1562
  /// Subtract Packed FP16 Values.
  | VSUBPH = 1563
  /// Subtract Packed Single Precision Floating-Point Values.
  | VSUBPS = 1564
  /// Subtract Scalar Double Precision Floating-Point Value.
  | VSUBSD = 1565
  /// Subtract Scalar FP16 Value.
  | VSUBSH = 1566
  /// Subtract Scalar Single Precision Floating-Point Value.
  | VSUBSS = 1567
  /// Packed Bit Test.
  | VTESTPD = 1568
  /// Packed Bit Test.
  | VTESTPS = 1569
  /// Unordered Compare Scalar Double Precision Floating-Point Values and Set
  /// EFLAGS.
  | VUCOMISD = 1570
  /// Unordered Compare Scalar FP16 Values and Set EFLAGS.
  | VUCOMISH = 1571
  /// Unordered Compare Scalar Single Precision Floating-Point Values and Set
  /// EFLAGS.
  | VUCOMISS = 1572
  /// Unpack and Interleave High Packed Double Precision Floating-Point Values.
  | VUNPCKHPD = 1573
  /// Unpack and Interleave High Packed Single Precision Floating-Point Values.
  | VUNPCKHPS = 1574
  /// Unpack and Interleave Low Packed Double Precision Floating-Point Values.
  | VUNPCKLPD = 1575
  /// Unpack and Interleave Low Packed Single Precision Floating-Point Values.
  | VUNPCKLPS = 1576
  /// Bitwise Logical XOR of Packed Double Precision Floating-Point Values.
  | VXORPD = 1577
  /// Bitwise Logical XOR of Packed Single Precision Floating-Point Values.
  | VXORPS = 1578
  /// Zero XMM, YMM, and ZMM Registers.
  | VZEROALL = 1579
  /// Zero Upper Bits of YMM and ZMM Registers.
  | VZEROUPPER = 1580
  /// Wait.
  | WAIT = 1581
  /// Write Back and Invalidate Cache.
  | WBINVD = 1582
  /// Write Back and Do Not Invalidate Cache.
  | WBNOINVD = 1583
  /// Write FS/GS Segment Base.
  | WRFSBASE = 1584
  /// Write FS/GS Segment Base.
  | WRGSBASE = 1585
  /// Write to Model Specific Register.
  | WRMSR = 1586
  /// Write List of Model Specific Registers.
  | WRMSRLIST = 1587
  /// Non-Serializing Write to Model Specific Register.
  | WRMSRNS = 1588
  /// Write Data to User Page Key Register.
  | WRPKRU = 1589
  /// Write to Shadow Stack.
  | WRSSD = 1590
  /// Write to Shadow Stack.
  | WRSSQ = 1591
  /// Write to User Shadow Stack.
  | WRUSSD = 1592
  /// Write to User Shadow Stack.
  | WRUSSQ = 1593
  /// Transactional Abort.
  | XABORT = 1594
  /// Hardware Lock Elision Prefix Hints.
  | XACQUIRE = 1595
  /// Exchange and Add.
  | XADD = 1596
  /// Transactional Begin.
  | XBEGIN = 1597
  /// Exchange Register/Memory With Register.
  | XCHG = 1598
  /// Cipher Block Chaining.
  | XCRYPTCBC = 1599
  /// Cipher Feedback Mode.
  | XCRYPTCFB = 1600
  /// Counter Mode (ACE2).
  | XCRYPTCTR = 1601
  /// Electronic code book.
  | XCRYPTECB = 1602
  /// Output Feedback Mode.
  | XCRYPTOFB = 1603
  /// Transactional End.
  | XEND = 1604
  /// Get Value of Extended Control Register.
  | XGETBV = 1605
  /// Table Look-up Translation.
  | XLAT = 1606
  /// Table Look-up Translation.
  | XLATB = 1607
  /// Modular Multiplication.
  | XMODEXP = 1608
  /// Logical Exclusive OR.
  | XOR = 1609
  /// Bitwise Logical XOR of Packed Double Precision Floating-Point Values.
  | XORPD = 1610
  /// Bitwise Logical XOR of Packed Single Precision Floating-Point Values.
  | XORPS = 1611
  /// Hardware Lock Elision Prefix Hints.
  | XRELEASE = 1612
  /// Resume Tracking Load Addresses.
  | XRESLDTRK = 1613
  /// Random Number Generation.
  | XRNG2 = 1614
  /// Restore Processor Extended States.
  | XRSTOR = 1615
  /// Restore state components specified by EDX:EAX from mem.
  | XRSTOR64 = 1616
  /// Restore Processor Extended States Supervisor.
  | XRSTORS = 1617
  /// Restore state components specified by EDX:EAX from mem.
  | XRSTORS64 = 1618
  /// Save Processor Extended States.
  | XSAVE = 1619
  /// Save state components specified by EDX:EAX to mem.
  | XSAVE64 = 1620
  /// Save Processor Extended States With Compaction.
  | XSAVEC = 1621
  /// Save state components specified by EDX:EAX to mem with compaction.
  | XSAVEC64 = 1622
  /// Save Processor Extended States Optimized.
  | XSAVEOPT = 1623
  /// Save state components specified by EDX:EAX to mem, optimizing if possible.
  | XSAVEOPT64 = 1624
  /// Save Processor Extended States Supervisor.
  | XSAVES = 1625
  /// Save state components specified by EDX:EAX to mem with compaction,
  /// optimizing if possible.
  | XSAVES64 = 1626
  /// Set Extended Control Register.
  | XSETBV = 1627
  /// Hash Function SHA-1.
  | XSHA1 = 1628
  /// Hash Function SHA-256.
  | XSHA256 = 1629
  /// Hash Function SHA-384.
  | XSHA384 = 1630
  /// Hash Function SHA-512.
  | XSHA512 = 1631
  /// Store Available Random Bytes.
  | XSTORERNG = 1632
  /// Suspend Tracking Load Addresses.
  | XSUSLDTRK = 1633
  /// Test if in Transactional Execution.
  | XTEST = 1634
  /// Invalid Opcode.
  | InvalOP = 1635

/// Provides functions to check properties of opcodes.
[<RequireQualifiedAccess>]
module internal Opcode =
  let isBranch = function
    | Opcode.CALL | Opcode.JMP | Opcode.RET
    | Opcode.JO
    | Opcode.JNO
    | Opcode.JB | Opcode.JC | Opcode.JNAE
    | Opcode.JAE | Opcode.JNB | Opcode.JNC
    | Opcode.JE | Opcode.JZ
    | Opcode.JNE | Opcode.JNZ
    | Opcode.JBE | Opcode.JNA
    | Opcode.JA | Opcode.JNBE
    | Opcode.JNS
    | Opcode.JP | Opcode.JPE
    | Opcode.JNP | Opcode.JPO
    | Opcode.JL | Opcode.JNGE
    | Opcode.JGE | Opcode.JNL
    | Opcode.JLE | Opcode.JNG
    | Opcode.JG | Opcode.JNLE
    | Opcode.JS
    | Opcode.JCXZ | Opcode.JECXZ | Opcode.JRCXZ
    | Opcode.LOOP| Opcode.LOOPE | Opcode.LOOPNE -> true
    | _ -> false

  let isCETInstr = function
    | Opcode.INCSSPD | Opcode.INCSSPQ | Opcode.RDSSPD | Opcode.RDSSPQ
    | Opcode.SAVEPREVSSP | Opcode.RSTORSSP | Opcode.WRSSD | Opcode.WRSSQ
    | Opcode.WRUSSD | Opcode.WRUSSQ | Opcode.SETSSBSY | Opcode.CLRSSBSY ->
      true
    | _ -> false

  let opcodeToString = function
    | Opcode.AAA -> "aaa"
    | Opcode.AAD -> "aad"
    | Opcode.AAM -> "aam"
    | Opcode.AAS -> "aas"
    | Opcode.ADC -> "adc"
    | Opcode.ADCX -> "adcx"
    | Opcode.ADD -> "add"
    | Opcode.ADDPD -> "addpd"
    | Opcode.ADDPS -> "addps"
    | Opcode.ADDSD -> "addsd"
    | Opcode.ADDSS -> "addss"
    | Opcode.ADDSUBPD -> "addsubpd"
    | Opcode.ADDSUBPS -> "addsubps"
    | Opcode.ADOX -> "adox"
    | Opcode.AESDEC -> "aesdec"
    | Opcode.AESDEC128KL -> "aesdec128kl"
    | Opcode.AESDEC256KL -> "aesdec256kl"
    | Opcode.AESDECLAST -> "aesdeclast"
    | Opcode.AESDECWIDE128KL -> "aesdecwide128kl"
    | Opcode.AESDECWIDE256KL -> "aesdecwide256kl"
    | Opcode.AESENC -> "aesenc"
    | Opcode.AESENC128KL -> "aesenc128kl"
    | Opcode.AESENC256KL -> "aesenc256kl"
    | Opcode.AESENCLAST -> "aesenclast"
    | Opcode.AESENCWIDE128KL -> "aesencwide128kl"
    | Opcode.AESENCWIDE256KL -> "aesencwide256kl"
    | Opcode.AESIMC -> "aesimc"
    | Opcode.AESKEYGENASSIST -> "aeskeygenassist"
    | Opcode.AND -> "and"
    | Opcode.ANDN -> "andn"
    | Opcode.ANDNPD -> "andnpd"
    | Opcode.ANDNPS -> "andnps"
    | Opcode.ANDPD -> "andpd"
    | Opcode.ANDPS -> "andps"
    | Opcode.ARPL -> "arpl"
    | Opcode.BEXTR -> "bextr"
    | Opcode.BLENDPD -> "blendpd"
    | Opcode.BLENDPS -> "blendps"
    | Opcode.BLENDVPD -> "blendvpd"
    | Opcode.BLENDVPS -> "blendvps"
    | Opcode.BLSI -> "blsi"
    | Opcode.BLSMSK -> "blsmsk"
    | Opcode.BLSR -> "blsr"
    | Opcode.BNDCL -> "bndcl"
    | Opcode.BNDCN -> "bndcn"
    | Opcode.BNDCU -> "bndcu"
    | Opcode.BNDLDX -> "bndldx"
    | Opcode.BNDMK -> "bndmk"
    | Opcode.BNDMOV -> "bndmov"
    | Opcode.BNDSTX -> "bndstx"
    | Opcode.BOUND -> "bound"
    | Opcode.BSF -> "bsf"
    | Opcode.BSR -> "bsr"
    | Opcode.BSWAP -> "bswap"
    | Opcode.BT -> "bt"
    | Opcode.BTC -> "btc"
    | Opcode.BTR -> "btr"
    | Opcode.BTS -> "bts"
    | Opcode.BZHI -> "bzhi"
    | Opcode.CALL -> "call"
    | Opcode.CBW -> "cbw"
    | Opcode.CCS_ENCRYPT -> "ccs_encrypt"
    | Opcode.CCS_HASH -> "ccs_hash"
    | Opcode.CDQ -> "cdq"
    | Opcode.CDQE -> "cdqe"
    | Opcode.CLAC -> "clac"
    | Opcode.CLC -> "clc"
    | Opcode.CLD -> "cld"
    | Opcode.CLDEMOTE -> "cldemote"
    | Opcode.CLFLUSH -> "clflush"
    | Opcode.CLFLUSHOPT -> "clflushopt"
    | Opcode.CLI -> "cli"
    | Opcode.CLRSSBSY -> "clrssbsy"
    | Opcode.CLTS -> "clts"
    | Opcode.CLUI -> "clui"
    | Opcode.CLWB -> "clwb"
    | Opcode.CMC -> "cmc"
    | Opcode.CMOVA -> "cmova"
    | Opcode.CMOVAE -> "cmovae"
    | Opcode.CMOVB -> "cmovb"
    | Opcode.CMOVBE -> "cmovbe"
    | Opcode.CMOVC -> "cmovc"
    | Opcode.CMOVE -> "cmove"
    | Opcode.CMOVG -> "cmovg"
    | Opcode.CMOVGE -> "cmovge"
    | Opcode.CMOVL -> "cmovl"
    | Opcode.CMOVLE -> "cmovle"
    | Opcode.CMOVNA -> "cmovna"
    | Opcode.CMOVNAE -> "cmovnae"
    | Opcode.CMOVNB -> "cmovnb"
    | Opcode.CMOVNBE -> "cmovnbe"
    | Opcode.CMOVNC -> "cmovnc"
    | Opcode.CMOVNE -> "cmovne"
    | Opcode.CMOVNG -> "cmovng"
    | Opcode.CMOVNGE -> "cmovnge"
    | Opcode.CMOVNL -> "cmovnl"
    | Opcode.CMOVNLE -> "cmovnle"
    | Opcode.CMOVNO -> "cmovno"
    | Opcode.CMOVNP -> "cmovnp"
    | Opcode.CMOVNS -> "cmovns"
    | Opcode.CMOVNZ -> "cmovnz"
    | Opcode.CMOVO -> "cmovo"
    | Opcode.CMOVP -> "cmovp"
    | Opcode.CMOVPE -> "cmovpe"
    | Opcode.CMOVPO -> "cmovpo"
    | Opcode.CMOVS -> "cmovs"
    | Opcode.CMOVZ -> "cmovz"
    | Opcode.CMP -> "cmp"
    | Opcode.CMPBEXADD -> "cmpbexadd"
    | Opcode.CMPBXADD -> "cmpbxadd"
    | Opcode.CMPLEXADD -> "cmplexadd"
    | Opcode.CMPLXADD -> "cmplxadd"
    | Opcode.CMPNBEXADD -> "cmpnbexadd"
    | Opcode.CMPNBXADD -> "cmpnbxadd"
    | Opcode.CMPNLEXADD -> "cmpnlexadd"
    | Opcode.CMPNLXADD -> "cmpnlxadd"
    | Opcode.CMPNOXADD -> "cmpnoxadd"
    | Opcode.CMPNPXADD -> "cmpnpxadd"
    | Opcode.CMPNSXADD -> "cmpnsxadd"
    | Opcode.CMPNZXADD -> "cmpnzxadd"
    | Opcode.CMPOXADD -> "cmpoxadd"
    | Opcode.CMPPD -> "cmppd"
    | Opcode.CMPPS -> "cmpps"
    | Opcode.CMPPXADD -> "cmppxadd"
    | Opcode.CMPS -> "cmps"
    | Opcode.CMPSB -> "cmpsb"
    | Opcode.CMPSD -> "cmpsd"
    | Opcode.CMPSQ -> "cmpsq"
    | Opcode.CMPSS -> "cmpss"
    | Opcode.CMPSW -> "cmpsw"
    | Opcode.CMPSXADD -> "cmpsxadd"
    | Opcode.CMPXCHG -> "cmpxchg"
    | Opcode.CMPXCHG16B -> "cmpxchg16b"
    | Opcode.CMPXCHG8B -> "cmpxchg8b"
    | Opcode.CMPZXADD -> "cmpzxadd"
    | Opcode.COMISD -> "comisd"
    | Opcode.COMISS -> "comiss"
    | Opcode.CPUID -> "cpuid"
    | Opcode.CQO -> "cqo"
    | Opcode.CRC32 -> "crc32"
    | Opcode.CVTDQ2PD -> "cvtdq2pd"
    | Opcode.CVTDQ2PS -> "cvtdq2ps"
    | Opcode.CVTPD2DQ -> "cvtpd2dq"
    | Opcode.CVTPD2PI -> "cvtpd2pi"
    | Opcode.CVTPD2PS -> "cvtpd2ps"
    | Opcode.CVTPI2PD -> "cvtpi2pd"
    | Opcode.CVTPI2PS -> "cvtpi2ps"
    | Opcode.CVTPS2DQ -> "cvtps2dq"
    | Opcode.CVTPS2PD -> "cvtps2pd"
    | Opcode.CVTPS2PI -> "cvtps2pi"
    | Opcode.CVTSD2SI -> "cvtsd2si"
    | Opcode.CVTSD2SS -> "cvtsd2ss"
    | Opcode.CVTSI2SD -> "cvtsi2sd"
    | Opcode.CVTSI2SS -> "cvtsi2ss"
    | Opcode.CVTSS2SD -> "cvtss2sd"
    | Opcode.CVTSS2SI -> "cvtss2si"
    | Opcode.CVTTPD2DQ -> "cvttpd2dq"
    | Opcode.CVTTPD2PI -> "cvttpd2pi"
    | Opcode.CVTTPS2DQ -> "cvttps2dq"
    | Opcode.CVTTPS2PI -> "cvttps2pi"
    | Opcode.CVTTSD2SI -> "cvttsd2si"
    | Opcode.CVTTSS2SI -> "cvttss2si"
    | Opcode.CWD -> "cwd"
    | Opcode.CWDE -> "cwde"
    | Opcode.DAA -> "daa"
    | Opcode.DAS -> "das"
    | Opcode.DEC -> "dec"
    | Opcode.DIV -> "div"
    | Opcode.DIVPD -> "divpd"
    | Opcode.DIVPS -> "divps"
    | Opcode.DIVSD -> "divsd"
    | Opcode.DIVSS -> "divss"
    | Opcode.DPPD -> "dppd"
    | Opcode.DPPS -> "dpps"
    | Opcode.EMMS -> "emms"
    | Opcode.ENCODEKEY128 -> "encodekey128"
    | Opcode.ENCODEKEY256 -> "encodekey256"
    | Opcode.ENDBR32 -> "endbr32"
    | Opcode.ENDBR64 -> "endbr64"
    | Opcode.ENQCMD -> "enqcmd"
    | Opcode.ENQCMDS -> "enqcmds"
    | Opcode.ENTER -> "enter"
    | Opcode.EXTRACTPS -> "extractps"
    | Opcode.EXTRQ -> "extrq"
    | Opcode.F2XM1 -> "f2xm1"
    | Opcode.FABS -> "fabs"
    | Opcode.FADD -> "fadd"
    | Opcode.FADDP -> "faddp"
    | Opcode.FBLD -> "fbld"
    | Opcode.FBSTP -> "fbstp"
    | Opcode.FCHS -> "fchs"
    | Opcode.FCLEX -> "fclex"
    | Opcode.FCMOVB -> "fcmovb"
    | Opcode.FCMOVBE -> "fcmovbe"
    | Opcode.FCMOVE -> "fcmove"
    | Opcode.FCMOVNB -> "fcmovnb"
    | Opcode.FCMOVNBE -> "fcmovnbe"
    | Opcode.FCMOVNE -> "fcmovne"
    | Opcode.FCMOVNU -> "fcmovnu"
    | Opcode.FCMOVU -> "fcmovu"
    | Opcode.FCOM -> "fcom"
    | Opcode.FCOMI -> "fcomi"
    | Opcode.FCOMIP -> "fcomip"
    | Opcode.FCOMP -> "fcomp"
    | Opcode.FCOMPP -> "fcompp"
    | Opcode.FCOS -> "fcos"
    | Opcode.FDECSTP -> "fdecstp"
    | Opcode.FDIV -> "fdiv"
    | Opcode.FDIVP -> "fdivp"
    | Opcode.FDIVR -> "fdivr"
    | Opcode.FDIVRP -> "fdivrp"
    | Opcode.FFREE -> "ffree"
    | Opcode.FFREEP -> "ffreep"
    | Opcode.FIADD -> "fiadd"
    | Opcode.FICOM -> "ficom"
    | Opcode.FICOMP -> "ficomp"
    | Opcode.FIDIV -> "fidiv"
    | Opcode.FIDIVR -> "fidivr"
    | Opcode.FILD -> "fild"
    | Opcode.FIMUL -> "fimul"
    | Opcode.FINCSTP -> "fincstp"
    | Opcode.FINIT -> "finit"
    | Opcode.FIST -> "fist"
    | Opcode.FISTP -> "fistp"
    | Opcode.FISTTP -> "fisttp"
    | Opcode.FISUB -> "fisub"
    | Opcode.FISUBR -> "fisubr"
    | Opcode.FLD -> "fld"
    | Opcode.FLD1 -> "fld1"
    | Opcode.FLDCW -> "fldcw"
    | Opcode.FLDENV -> "fldenv"
    | Opcode.FLDL2E -> "fldl2e"
    | Opcode.FLDL2T -> "fldl2t"
    | Opcode.FLDLG2 -> "fldlg2"
    | Opcode.FLDLN2 -> "fldln2"
    | Opcode.FLDPI -> "fldpi"
    | Opcode.FLDZ -> "fldz"
    | Opcode.FMUL -> "fmul"
    | Opcode.FMULP -> "fmulp"
    | Opcode.FNCLEX -> "fnclex"
    | Opcode.FNINIT -> "fninit"
    | Opcode.FNOP -> "fnop"
    | Opcode.FNSAVE -> "fnsave"
    | Opcode.FNSTCW -> "fnstcw"
    | Opcode.FNSTENV -> "fnstenv"
    | Opcode.FNSTSW -> "fnstsw"
    | Opcode.FPATAN -> "fpatan"
    | Opcode.FPREM -> "fprem"
    | Opcode.FPREM1 -> "fprem1"
    | Opcode.FPTAN -> "fptan"
    | Opcode.FRNDINT -> "frndint"
    | Opcode.FRSTOR -> "frstor"
    | Opcode.FSAVE -> "fsave"
    | Opcode.FSCALE -> "fscale"
    | Opcode.FSIN -> "fsin"
    | Opcode.FSINCOS -> "fsincos"
    | Opcode.FSQRT -> "fsqrt"
    | Opcode.FST -> "fst"
    | Opcode.FSTCW -> "fstcw"
    | Opcode.FSTENV -> "fstenv"
    | Opcode.FSTP -> "fstp"
    | Opcode.FSTSW -> "fstsw"
    | Opcode.FSUB -> "fsub"
    | Opcode.FSUBP -> "fsubp"
    | Opcode.FSUBR -> "fsubr"
    | Opcode.FSUBRP -> "fsubrp"
    | Opcode.FTST -> "ftst"
    | Opcode.FUCOM -> "fucom"
    | Opcode.FUCOMI -> "fucomi"
    | Opcode.FUCOMIP -> "fucomip"
    | Opcode.FUCOMP -> "fucomp"
    | Opcode.FUCOMPP -> "fucompp"
    | Opcode.FWAIT -> "fwait"
    | Opcode.FXAM -> "fxam"
    | Opcode.FXCH -> "fxch"
    | Opcode.FXRSTOR -> "fxrstor"
    | Opcode.FXRSTOR64 -> "fxrstor64"
    | Opcode.FXSAVE -> "fxsave"
    | Opcode.FXSAVE64 -> "fxsave64"
    | Opcode.FXTRACT -> "fxtract"
    | Opcode.FYL2X -> "fyl2x"
    | Opcode.FYL2XP1 -> "fyl2xp1"
    | Opcode.GETSEC -> "getsec"
    | Opcode.GF2P8AFFINEINVQB -> "gf2p8affineinvqb"
    | Opcode.GF2P8AFFINEQB -> "gf2p8affineqb"
    | Opcode.GF2P8MULB -> "gf2p8mulb"
    | Opcode.HADDPD -> "haddpd"
    | Opcode.HADDPS -> "haddps"
    | Opcode.HLT -> "hlt"
    | Opcode.HRESET -> "hreset"
    | Opcode.HSUBPD -> "hsubpd"
    | Opcode.HSUBPS -> "hsubps"
    | Opcode.IDIV -> "idiv"
    | Opcode.IMUL -> "imul"
    | Opcode.IN -> "in"
    | Opcode.INC -> "inc"
    | Opcode.INCSSPD -> "incsspd"
    | Opcode.INCSSPQ -> "incsspq"
    | Opcode.INS -> "ins"
    | Opcode.INSB -> "insb"
    | Opcode.INSD -> "insd"
    | Opcode.INSERTPS -> "insertps"
    | Opcode.INSERTQ -> "insertq"
    | Opcode.INSW -> "insw"
    | Opcode.INT -> "int"
    | Opcode.INT1 -> "int1"
    | Opcode.INT3 -> "int3"
    | Opcode.INTO -> "into"
    | Opcode.INVD -> "invd"
    | Opcode.INVLPG -> "invlpg"
    | Opcode.INVPCID -> "invpcid"
    | Opcode.IRET -> "iret"
    | Opcode.IRETD -> "iretd"
    | Opcode.IRETQ -> "iretq"
    | Opcode.IRETW -> "iretw"
    | Opcode.JA -> "ja"
    | Opcode.JAE -> "jae"
    | Opcode.JB -> "jb"
    | Opcode.JBE -> "jbe"
    | Opcode.JC -> "jc"
    | Opcode.JCXZ -> "jcxz"
    | Opcode.JE -> "je"
    | Opcode.JECXZ -> "jecxz"
    | Opcode.JG -> "jg"
    | Opcode.JGE -> "jge"
    | Opcode.JL -> "jl"
    | Opcode.JLE -> "jle"
    | Opcode.JMP -> "jmp"
    | Opcode.JNA -> "jna"
    | Opcode.JNAE -> "jnae"
    | Opcode.JNB -> "jnb"
    | Opcode.JNBE -> "jnbe"
    | Opcode.JNC -> "jnc"
    | Opcode.JNE -> "jne"
    | Opcode.JNG -> "jng"
    | Opcode.JNGE -> "jnge"
    | Opcode.JNL -> "jnl"
    | Opcode.JNLE -> "jnle"
    | Opcode.JNO -> "jno"
    | Opcode.JNP -> "jnp"
    | Opcode.JNS -> "jns"
    | Opcode.JNZ -> "jnz"
    | Opcode.JO -> "jo"
    | Opcode.JP -> "jp"
    | Opcode.JPE -> "jpe"
    | Opcode.JPO -> "jpo"
    | Opcode.JRCXZ -> "jrcxz"
    | Opcode.JS -> "js"
    | Opcode.JZ -> "jz"
    | Opcode.KADDB -> "kaddb"
    | Opcode.KADDD -> "kaddd"
    | Opcode.KADDQ -> "kaddq"
    | Opcode.KADDW -> "kaddw"
    | Opcode.KANDB -> "kandb"
    | Opcode.KANDD -> "kandd"
    | Opcode.KANDNB -> "kandnb"
    | Opcode.KANDND -> "kandnd"
    | Opcode.KANDNQ -> "kandnq"
    | Opcode.KANDNW -> "kandnw"
    | Opcode.KANDQ -> "kandq"
    | Opcode.KANDW -> "kandw"
    | Opcode.KMOVB -> "kmovb"
    | Opcode.KMOVD -> "kmovd"
    | Opcode.KMOVQ -> "kmovq"
    | Opcode.KMOVW -> "kmovw"
    | Opcode.KNOTB -> "knotb"
    | Opcode.KNOTD -> "knotd"
    | Opcode.KNOTQ -> "knotq"
    | Opcode.KNOTW -> "knotw"
    | Opcode.KORB -> "korb"
    | Opcode.KORD -> "kord"
    | Opcode.KORQ -> "korq"
    | Opcode.KORTESTB -> "kortestb"
    | Opcode.KORTESTD -> "kortestd"
    | Opcode.KORTESTQ -> "kortestq"
    | Opcode.KORTESTW -> "kortestw"
    | Opcode.KORW -> "korw"
    | Opcode.KSHIFTLB -> "kshiftlb"
    | Opcode.KSHIFTLD -> "kshiftld"
    | Opcode.KSHIFTLQ -> "kshiftlq"
    | Opcode.KSHIFTLW -> "kshiftlw"
    | Opcode.KSHIFTRB -> "kshiftrb"
    | Opcode.KSHIFTRD -> "kshiftrd"
    | Opcode.KSHIFTRQ -> "kshiftrq"
    | Opcode.KSHIFTRW -> "kshiftrw"
    | Opcode.KTESTB -> "ktestb"
    | Opcode.KTESTD -> "ktestd"
    | Opcode.KTESTQ -> "ktestq"
    | Opcode.KTESTW -> "ktestw"
    | Opcode.KUNPCKBW -> "kunpckbw"
    | Opcode.KUNPCKDQ -> "kunpckdq"
    | Opcode.KUNPCKWD -> "kunpckwd"
    | Opcode.KXNORB -> "kxnorb"
    | Opcode.KXNORD -> "kxnord"
    | Opcode.KXNORQ -> "kxnorq"
    | Opcode.KXNORW -> "kxnorw"
    | Opcode.KXORB -> "kxorb"
    | Opcode.KXORD -> "kxord"
    | Opcode.KXORQ -> "kxorq"
    | Opcode.KXORW -> "kxorw"
    | Opcode.LAHF -> "lahf"
    | Opcode.LAR -> "lar"
    | Opcode.LDDQU -> "lddqu"
    | Opcode.LDMXCSR -> "ldmxcsr"
    | Opcode.LDS -> "lds"
    | Opcode.LDTILECFG -> "ldtilecfg"
    | Opcode.LEA -> "lea"
    | Opcode.LEAVE -> "leave"
    | Opcode.LES -> "les"
    | Opcode.LFENCE -> "lfence"
    | Opcode.LFS -> "lfs"
    | Opcode.LGDT -> "lgdt"
    | Opcode.LGS -> "lgs"
    | Opcode.LIDT -> "lidt"
    | Opcode.LLDT -> "lldt"
    | Opcode.LMSW -> "lmsw"
    | Opcode.LOADIWKEY -> "loadiwkey"
    | Opcode.LOCK -> "lock"
    | Opcode.LODS -> "lods"
    | Opcode.LODSB -> "lodsb"
    | Opcode.LODSD -> "lodsd"
    | Opcode.LODSQ -> "lodsq"
    | Opcode.LODSW -> "lodsw"
    | Opcode.LOOP -> "loop"
    | Opcode.LOOPE -> "loope"
    | Opcode.LOOPNE -> "loopne"
    | Opcode.LSL -> "lsl"
    | Opcode.LSS -> "lss"
    | Opcode.LTR -> "ltr"
    | Opcode.LZCNT -> "lzcnt"
    | Opcode.MASKMOVDQU -> "maskmovdqu"
    | Opcode.MASKMOVQ -> "maskmovq"
    | Opcode.MAXPD -> "maxpd"
    | Opcode.MAXPS -> "maxps"
    | Opcode.MAXSD -> "maxsd"
    | Opcode.MAXSS -> "maxss"
    | Opcode.MFENCE -> "mfence"
    | Opcode.MINPD -> "minpd"
    | Opcode.MINPS -> "minps"
    | Opcode.MINSD -> "minsd"
    | Opcode.MINSS -> "minss"
    | Opcode.MONITOR -> "monitor"
    | Opcode.MONTMUL -> "montmul"
    | Opcode.MONTMUL2 -> "montmul2"
    | Opcode.MOV -> "mov"
    | Opcode.MOVAPD -> "movapd"
    | Opcode.MOVAPS -> "movaps"
    | Opcode.MOVBE -> "movbe"
    | Opcode.MOVD -> "movd"
    | Opcode.MOVDDUP -> "movddup"
    | Opcode.MOVDIR64B -> "movdir64b"
    | Opcode.MOVDIRI -> "movdiri"
    | Opcode.MOVDQ2Q -> "movdq2q"
    | Opcode.MOVDQA -> "movdqa"
    | Opcode.MOVDQU -> "movdqu"
    | Opcode.MOVHLPS -> "movhlps"
    | Opcode.MOVHPD -> "movhpd"
    | Opcode.MOVHPS -> "movhps"
    | Opcode.MOVLHPS -> "movlhps"
    | Opcode.MOVLPD -> "movlpd"
    | Opcode.MOVLPS -> "movlps"
    | Opcode.MOVMSKPD -> "movmskpd"
    | Opcode.MOVMSKPS -> "movmskps"
    | Opcode.MOVNTDQ -> "movntdq"
    | Opcode.MOVNTDQA -> "movntdqa"
    | Opcode.MOVNTI -> "movnti"
    | Opcode.MOVNTPD -> "movntpd"
    | Opcode.MOVNTPS -> "movntps"
    | Opcode.MOVNTQ -> "movntq"
    | Opcode.MOVQ -> "movq"
    | Opcode.MOVQ2DQ -> "movq2dq"
    | Opcode.MOVS -> "movs"
    | Opcode.MOVSB -> "movsb"
    | Opcode.MOVSD -> "movsd"
    | Opcode.MOVSHDUP -> "movshdup"
    | Opcode.MOVSLDUP -> "movsldup"
    | Opcode.MOVSQ -> "movsq"
    | Opcode.MOVSS -> "movss"
    | Opcode.MOVSW -> "movsw"
    | Opcode.MOVSX -> "movsx"
    | Opcode.MOVSXD -> "movsxd"
    | Opcode.MOVUPD -> "movupd"
    | Opcode.MOVUPS -> "movups"
    | Opcode.MOVZX -> "movzx"
    | Opcode.MPSADBW -> "mpsadbw"
    | Opcode.MUL -> "mul"
    | Opcode.MULPD -> "mulpd"
    | Opcode.MULPS -> "mulps"
    | Opcode.MULSD -> "mulsd"
    | Opcode.MULSS -> "mulss"
    | Opcode.MULX -> "mulx"
    | Opcode.MWAIT -> "mwait"
    | Opcode.NEG -> "neg"
    | Opcode.NOP -> "nop"
    | Opcode.NOT -> "not"
    | Opcode.OR -> "or"
    | Opcode.ORPD -> "orpd"
    | Opcode.ORPS -> "orps"
    | Opcode.OUT -> "out"
    | Opcode.OUTS -> "outs"
    | Opcode.OUTSB -> "outsb"
    | Opcode.OUTSD -> "outsd"
    | Opcode.OUTSW -> "outsw"
    | Opcode.PABSB -> "pabsb"
    | Opcode.PABSD -> "pabsd"
    | Opcode.PABSW -> "pabsw"
    | Opcode.PACKSSDW -> "packssdw"
    | Opcode.PACKSSWB -> "packsswb"
    | Opcode.PACKUSDW -> "packusdw"
    | Opcode.PACKUSWB -> "packuswb"
    | Opcode.PADDB -> "paddb"
    | Opcode.PADDD -> "paddd"
    | Opcode.PADDQ -> "paddq"
    | Opcode.PADDSB -> "paddsb"
    | Opcode.PADDSW -> "paddsw"
    | Opcode.PADDUSB -> "paddusb"
    | Opcode.PADDUSW -> "paddusw"
    | Opcode.PADDW -> "paddw"
    | Opcode.PALIGNR -> "palignr"
    | Opcode.PAND -> "pand"
    | Opcode.PANDN -> "pandn"
    | Opcode.PAUSE -> "pause"
    | Opcode.PAVGB -> "pavgb"
    | Opcode.PAVGW -> "pavgw"
    | Opcode.PBLENDVB -> "pblendvb"
    | Opcode.PBLENDW -> "pblendw"
    | Opcode.PCLMULQDQ -> "pclmulqdq"
    | Opcode.PCMPEQB -> "pcmpeqb"
    | Opcode.PCMPEQD -> "pcmpeqd"
    | Opcode.PCMPEQQ -> "pcmpeqq"
    | Opcode.PCMPEQW -> "pcmpeqw"
    | Opcode.PCMPESTRI -> "pcmpestri"
    | Opcode.PCMPESTRM -> "pcmpestrm"
    | Opcode.PCMPGTB -> "pcmpgtb"
    | Opcode.PCMPGTD -> "pcmpgtd"
    | Opcode.PCMPGTQ -> "pcmpgtq"
    | Opcode.PCMPGTW -> "pcmpgtw"
    | Opcode.PCMPISTRI -> "pcmpistri"
    | Opcode.PCMPISTRM -> "pcmpistrm"
    | Opcode.PCONFIG -> "pconfig"
    | Opcode.PDEP -> "pdep"
    | Opcode.PEXT -> "pext"
    | Opcode.PEXTRB -> "pextrb"
    | Opcode.PEXTRD -> "pextrd"
    | Opcode.PEXTRQ -> "pextrq"
    | Opcode.PEXTRW -> "pextrw"
    | Opcode.PHADDD -> "phaddd"
    | Opcode.PHADDSW -> "phaddsw"
    | Opcode.PHADDW -> "phaddw"
    | Opcode.PHMINPOSUW -> "phminposuw"
    | Opcode.PHSUBD -> "phsubd"
    | Opcode.PHSUBSW -> "phsubsw"
    | Opcode.PHSUBW -> "phsubw"
    | Opcode.PINSRB -> "pinsrb"
    | Opcode.PINSRD -> "pinsrd"
    | Opcode.PINSRQ -> "pinsrq"
    | Opcode.PINSRW -> "pinsrw"
    | Opcode.PMADDUBSW -> "pmaddubsw"
    | Opcode.PMADDWD -> "pmaddwd"
    | Opcode.PMAXSB -> "pmaxsb"
    | Opcode.PMAXSD -> "pmaxsd"
    | Opcode.PMAXSW -> "pmaxsw"
    | Opcode.PMAXUB -> "pmaxub"
    | Opcode.PMAXUD -> "pmaxud"
    | Opcode.PMAXUW -> "pmaxuw"
    | Opcode.PMINSB -> "pminsb"
    | Opcode.PMINSD -> "pminsd"
    | Opcode.PMINSW -> "pminsw"
    | Opcode.PMINUB -> "pminub"
    | Opcode.PMINUD -> "pminud"
    | Opcode.PMINUW -> "pminuw"
    | Opcode.PMOVMSKB -> "pmovmskb"
    | Opcode.PMOVSXBD -> "pmovsxbd"
    | Opcode.PMOVSXBQ -> "pmovsxbq"
    | Opcode.PMOVSXBW -> "pmovsxbw"
    | Opcode.PMOVSXDQ -> "pmovsxdq"
    | Opcode.PMOVSXWD -> "pmovsxwd"
    | Opcode.PMOVSXWQ -> "pmovsxwq"
    | Opcode.PMOVZXBD -> "pmovzxbd"
    | Opcode.PMOVZXBQ -> "pmovzxbq"
    | Opcode.PMOVZXBW -> "pmovzxbw"
    | Opcode.PMOVZXDQ -> "pmovzxdq"
    | Opcode.PMOVZXWD -> "pmovzxwd"
    | Opcode.PMOVZXWQ -> "pmovzxwq"
    | Opcode.PMULDQ -> "pmuldq"
    | Opcode.PMULHRSW -> "pmulhrsw"
    | Opcode.PMULHUW -> "pmulhuw"
    | Opcode.PMULHW -> "pmulhw"
    | Opcode.PMULLD -> "pmulld"
    | Opcode.PMULLW -> "pmullw"
    | Opcode.PMULUDQ -> "pmuludq"
    | Opcode.POP -> "pop"
    | Opcode.POPA -> "popa"
    | Opcode.POPAD -> "popad"
    | Opcode.POPCNT -> "popcnt"
    | Opcode.POPF -> "popf"
    | Opcode.POPFD -> "popfd"
    | Opcode.POPFQ -> "popfq"
    | Opcode.POR -> "por"
    | Opcode.PREFETCHIT0 -> "prefetchit0"
    | Opcode.PREFETCHIT1 -> "prefetchit1"
    | Opcode.PREFETCHNTA -> "prefetchnta"
    | Opcode.PREFETCHT0 -> "prefetcht0"
    | Opcode.PREFETCHT1 -> "prefetcht1"
    | Opcode.PREFETCHT2 -> "prefetcht2"
    | Opcode.PREFETCHW -> "prefetchw"
    | Opcode.PREFETCHWT1 -> "prefetchwt1"
    | Opcode.PSADBW -> "psadbw"
    | Opcode.PSHUFB -> "pshufb"
    | Opcode.PSHUFD -> "pshufd"
    | Opcode.PSHUFHW -> "pshufhw"
    | Opcode.PSHUFLW -> "pshuflw"
    | Opcode.PSHUFW -> "pshufw"
    | Opcode.PSIGNB -> "psignb"
    | Opcode.PSIGND -> "psignd"
    | Opcode.PSIGNW -> "psignw"
    | Opcode.PSLLD -> "pslld"
    | Opcode.PSLLDQ -> "pslldq"
    | Opcode.PSLLQ -> "psllq"
    | Opcode.PSLLW -> "psllw"
    | Opcode.PSRAD -> "psrad"
    | Opcode.PSRAW -> "psraw"
    | Opcode.PSRLD -> "psrld"
    | Opcode.PSRLDQ -> "psrldq"
    | Opcode.PSRLQ -> "psrlq"
    | Opcode.PSRLW -> "psrlw"
    | Opcode.PSUBB -> "psubb"
    | Opcode.PSUBD -> "psubd"
    | Opcode.PSUBQ -> "psubq"
    | Opcode.PSUBSB -> "psubsb"
    | Opcode.PSUBSW -> "psubsw"
    | Opcode.PSUBUSB -> "psubusb"
    | Opcode.PSUBUSW -> "psubusw"
    | Opcode.PSUBW -> "psubw"
    | Opcode.PTEST -> "ptest"
    | Opcode.PTWRITE -> "ptwrite"
    | Opcode.PUNPCKHBW -> "punpckhbw"
    | Opcode.PUNPCKHDQ -> "punpckhdq"
    | Opcode.PUNPCKHQDQ -> "punpckhqdq"
    | Opcode.PUNPCKHWD -> "punpckhwd"
    | Opcode.PUNPCKLBW -> "punpcklbw"
    | Opcode.PUNPCKLDQ -> "punpckldq"
    | Opcode.PUNPCKLQDQ -> "punpcklqdq"
    | Opcode.PUNPCKLWD -> "punpcklwd"
    | Opcode.PUSH -> "push"
    | Opcode.PUSHA -> "pusha"
    | Opcode.PUSHAD -> "pushad"
    | Opcode.PUSHF -> "pushf"
    | Opcode.PUSHFD -> "pushfd"
    | Opcode.PUSHFQ -> "pushfq"
    | Opcode.PXOR -> "pxor"
    | Opcode.RCL -> "rcl"
    | Opcode.RCPPS -> "rcpps"
    | Opcode.RCPSS -> "rcpss"
    | Opcode.RCR -> "rcr"
    | Opcode.RDFSBASE -> "rdfsbase"
    | Opcode.RDGSBASE -> "rdgsbase"
    | Opcode.RDMSR -> "rdmsr"
    | Opcode.RDMSRLIST -> "rdmsrlist"
    | Opcode.RDPID -> "rdpid"
    | Opcode.RDPKRU -> "rdpkru"
    | Opcode.RDPMC -> "rdpmc"
    | Opcode.RDRAND -> "rdrand"
    | Opcode.RDSEED -> "rdseed"
    | Opcode.RDSSPD -> "rdsspd"
    | Opcode.RDSSPQ -> "rdsspq"
    | Opcode.RDTSC -> "rdtsc"
    | Opcode.RDTSCP -> "rdtscp"
    | Opcode.RET -> "ret"
    | Opcode.ROL -> "rol"
    | Opcode.ROR -> "ror"
    | Opcode.RORX -> "rorx"
    | Opcode.ROUNDPD -> "roundpd"
    | Opcode.ROUNDPS -> "roundps"
    | Opcode.ROUNDSD -> "roundsd"
    | Opcode.ROUNDSS -> "roundss"
    | Opcode.RSM -> "rsm"
    | Opcode.RSQRTPS -> "rsqrtps"
    | Opcode.RSQRTSS -> "rsqrtss"
    | Opcode.RSTORSSP -> "rstorssp"
    | Opcode.SAHF -> "sahf"
    | Opcode.SAL -> "sal"
    | Opcode.SAR -> "sar"
    | Opcode.SARX -> "sarx"
    | Opcode.SAVEPREVSSP -> "saveprevssp"
    | Opcode.SBB -> "sbb"
    | Opcode.SCAS -> "scas"
    | Opcode.SCASB -> "scasb"
    | Opcode.SCASD -> "scasd"
    | Opcode.SCASQ -> "scasq"
    | Opcode.SCASW -> "scasw"
    | Opcode.SENDUIPI -> "senduipi"
    | Opcode.SERIALIZE -> "serialize"
    | Opcode.SETA -> "seta"
    | Opcode.SETAE -> "setae"
    | Opcode.SETB -> "setb"
    | Opcode.SETBE -> "setbe"
    | Opcode.SETC -> "setc"
    | Opcode.SETE -> "sete"
    | Opcode.SETG -> "setg"
    | Opcode.SETGE -> "setge"
    | Opcode.SETL -> "setl"
    | Opcode.SETLE -> "setle"
    | Opcode.SETNA -> "setna"
    | Opcode.SETNAE -> "setnae"
    | Opcode.SETNB -> "setnb"
    | Opcode.SETNBE -> "setnbe"
    | Opcode.SETNC -> "setnc"
    | Opcode.SETNE -> "setne"
    | Opcode.SETNG -> "setng"
    | Opcode.SETNGE -> "setnge"
    | Opcode.SETNL -> "setnl"
    | Opcode.SETNLE -> "setnle"
    | Opcode.SETNO -> "setno"
    | Opcode.SETNP -> "setnp"
    | Opcode.SETNS -> "setns"
    | Opcode.SETNZ -> "setnz"
    | Opcode.SETO -> "seto"
    | Opcode.SETP -> "setp"
    | Opcode.SETPE -> "setpe"
    | Opcode.SETPO -> "setpo"
    | Opcode.SETS -> "sets"
    | Opcode.SETSSBSY -> "setssbsy"
    | Opcode.SETZ -> "setz"
    | Opcode.SFENCE -> "sfence"
    | Opcode.SGDT -> "sgdt"
    | Opcode.SHA1MSG1 -> "sha1msg1"
    | Opcode.SHA1MSG2 -> "sha1msg2"
    | Opcode.SHA1NEXTE -> "sha1nexte"
    | Opcode.SHA1RNDS4 -> "sha1rnds4"
    | Opcode.SHA256MSG1 -> "sha256msg1"
    | Opcode.SHA256MSG2 -> "sha256msg2"
    | Opcode.SHA256RNDS2 -> "sha256rnds2"
    | Opcode.SHL -> "shl"
    | Opcode.SHLD -> "shld"
    | Opcode.SHLX -> "shlx"
    | Opcode.SHR -> "shr"
    | Opcode.SHRD -> "shrd"
    | Opcode.SHRX -> "shrx"
    | Opcode.SHUFPD -> "shufpd"
    | Opcode.SHUFPS -> "shufps"
    | Opcode.SIDT -> "sidt"
    | Opcode.SLDT -> "sldt"
    | Opcode.SM2 -> "sm2"
    | Opcode.SMSW -> "smsw"
    | Opcode.SQRTPD -> "sqrtpd"
    | Opcode.SQRTPS -> "sqrtps"
    | Opcode.SQRTSD -> "sqrtsd"
    | Opcode.SQRTSS -> "sqrtss"
    | Opcode.STAC -> "stac"
    | Opcode.STC -> "stc"
    | Opcode.STD -> "std"
    | Opcode.STI -> "sti"
    | Opcode.STMXCSR -> "stmxcsr"
    | Opcode.STOS -> "stos"
    | Opcode.STOSB -> "stosb"
    | Opcode.STOSD -> "stosd"
    | Opcode.STOSQ -> "stosq"
    | Opcode.STOSW -> "stosw"
    | Opcode.STR -> "str"
    | Opcode.STTILECFG -> "sttilecfg"
    | Opcode.STUI -> "stui"
    | Opcode.SUB -> "sub"
    | Opcode.SUBPD -> "subpd"
    | Opcode.SUBPS -> "subps"
    | Opcode.SUBSD -> "subsd"
    | Opcode.SUBSS -> "subss"
    | Opcode.SWAPGS -> "swapgs"
    | Opcode.SYSCALL -> "syscall"
    | Opcode.SYSENTER -> "sysenter"
    | Opcode.SYSEXIT -> "sysexit"
    | Opcode.SYSRET -> "sysret"
    | Opcode.TDPBF16PS -> "tdpbf16ps"
    | Opcode.TDPBSSD -> "tdpbssd"
    | Opcode.TDPBSUD -> "tdpbsud"
    | Opcode.TDPBUSD -> "tdpbusd"
    | Opcode.TDPBUUD -> "tdpbuud"
    | Opcode.TDPFP16PS -> "tdpfp16ps"
    | Opcode.TEST -> "test"
    | Opcode.TESTUI -> "testui"
    | Opcode.TILELOADD -> "tileloadd"
    | Opcode.TILELOADDT1 -> "tileloaddt1"
    | Opcode.TILERELEASE -> "tilerelease"
    | Opcode.TILESTORED -> "tilestored"
    | Opcode.TILEZERO -> "tilezero"
    | Opcode.TPAUSE -> "tpause"
    | Opcode.TZCNT -> "tzcnt"
    | Opcode.UCOMISD -> "ucomisd"
    | Opcode.UCOMISS -> "ucomiss"
    | Opcode.UD0 -> "ud0"
    | Opcode.UD1 -> "ud1"
    | Opcode.UD2 -> "ud2"
    | Opcode.UDB -> "udb"
    | Opcode.UIRET -> "uiret"
    | Opcode.UMONITOR -> "umonitor"
    | Opcode.UMWAIT -> "umwait"
    | Opcode.UNPCKHPD -> "unpckhpd"
    | Opcode.UNPCKHPS -> "unpckhps"
    | Opcode.UNPCKLPD -> "unpcklpd"
    | Opcode.UNPCKLPS -> "unpcklps"
    | Opcode.V4FMADDPS -> "v4fmaddps"
    | Opcode.V4FMADDSS -> "v4fmaddss"
    | Opcode.V4FNMADDPS -> "v4fnmaddps"
    | Opcode.V4FNMADDSS -> "v4fnmaddss"
    | Opcode.VADDPD -> "vaddpd"
    | Opcode.VADDPH -> "vaddph"
    | Opcode.VADDPS -> "vaddps"
    | Opcode.VADDSD -> "vaddsd"
    | Opcode.VADDSH -> "vaddsh"
    | Opcode.VADDSS -> "vaddss"
    | Opcode.VADDSUBPD -> "vaddsubpd"
    | Opcode.VADDSUBPS -> "vaddsubps"
    | Opcode.VAESDEC -> "vaesdec"
    | Opcode.VAESDECLAST -> "vaesdeclast"
    | Opcode.VAESENC -> "vaesenc"
    | Opcode.VAESENCLAST -> "vaesenclast"
    | Opcode.VAESIMC -> "vaesimc"
    | Opcode.VAESKEYGENASSIST -> "vaeskeygenassist"
    | Opcode.VALIGND -> "valignd"
    | Opcode.VALIGNQ -> "valignq"
    | Opcode.VANDNPD -> "vandnpd"
    | Opcode.VANDNPS -> "vandnps"
    | Opcode.VANDPD -> "vandpd"
    | Opcode.VANDPS -> "vandps"
    | Opcode.VBCSTNEBF162PS -> "vbcstnebf162ps"
    | Opcode.VBCSTNESH2PS -> "vbcstnesh2ps"
    | Opcode.VBLENDMPD -> "vblendmpd"
    | Opcode.VBLENDMPS -> "vblendmps"
    | Opcode.VBLENDPD -> "vblendpd"
    | Opcode.VBLENDPS -> "vblendps"
    | Opcode.VBLENDVPD -> "vblendvpd"
    | Opcode.VBLENDVPS -> "vblendvps"
    | Opcode.VBROADCASTF128 -> "vbroadcastf128"
    | Opcode.VBROADCASTF32X2 -> "vbroadcastf32x2"
    | Opcode.VBROADCASTF32X4 -> "vbroadcastf32x4"
    | Opcode.VBROADCASTF32X8 -> "vbroadcastf32x8"
    | Opcode.VBROADCASTF64X2 -> "vbroadcastf64x2"
    | Opcode.VBROADCASTF64X4 -> "vbroadcastf64x4"
    | Opcode.VBROADCASTI128 -> "vbroadcasti128"
    | Opcode.VBROADCASTI32X2 -> "vbroadcasti32x2"
    | Opcode.VBROADCASTI32X4 -> "vbroadcasti32x4"
    | Opcode.VBROADCASTI32X8 -> "vbroadcasti32x8"
    | Opcode.VBROADCASTI64X2 -> "vbroadcasti64x2"
    | Opcode.VBROADCASTI64X4 -> "vbroadcasti64x4"
    | Opcode.VBROADCASTSD -> "vbroadcastsd"
    | Opcode.VBROADCASTSS -> "vbroadcastss"
    | Opcode.VCMPPD -> "vcmppd"
    | Opcode.VCMPPH -> "vcmpph"
    | Opcode.VCMPPS -> "vcmpps"
    | Opcode.VCMPSD -> "vcmpsd"
    | Opcode.VCMPSH -> "vcmpsh"
    | Opcode.VCMPSS -> "vcmpss"
    | Opcode.VCOMISD -> "vcomisd"
    | Opcode.VCOMISH -> "vcomish"
    | Opcode.VCOMISS -> "vcomiss"
    | Opcode.VCOMPRESSPD -> "vcompresspd"
    | Opcode.VCOMPRESSPS -> "vcompressps"
    | Opcode.VCVTDQ2PD -> "vcvtdq2pd"
    | Opcode.VCVTDQ2PH -> "vcvtdq2ph"
    | Opcode.VCVTDQ2PS -> "vcvtdq2ps"
    | Opcode.VCVTNE2PS2BF16 -> "vcvtne2ps2bf16"
    | Opcode.VCVTNEEBF162PS -> "vcvtneebf162ps"
    | Opcode.VCVTNEEPH2PS -> "vcvtneeph2ps"
    | Opcode.VCVTNEOBF162PS -> "vcvtneobf162ps"
    | Opcode.VCVTNEOPH2PS -> "vcvtneoph2ps"
    | Opcode.VCVTNEPS2BF16 -> "vcvtneps2bf16"
    | Opcode.VCVTPD2DQ -> "vcvtpd2dq"
    | Opcode.VCVTPD2PH -> "vcvtpd2ph"
    | Opcode.VCVTPD2PS -> "vcvtpd2ps"
    | Opcode.VCVTPD2QQ -> "vcvtpd2qq"
    | Opcode.VCVTPD2UDQ -> "vcvtpd2udq"
    | Opcode.VCVTPD2UQQ -> "vcvtpd2uqq"
    | Opcode.VCVTPH2DQ -> "vcvtph2dq"
    | Opcode.VCVTPH2PD -> "vcvtph2pd"
    | Opcode.VCVTPH2PS -> "vcvtph2ps"
    | Opcode.VCVTPH2PSX -> "vcvtph2psx"
    | Opcode.VCVTPH2QQ -> "vcvtph2qq"
    | Opcode.VCVTPH2UDQ -> "vcvtph2udq"
    | Opcode.VCVTPH2UQQ -> "vcvtph2uqq"
    | Opcode.VCVTPH2UW -> "vcvtph2uw"
    | Opcode.VCVTPH2W -> "vcvtph2w"
    | Opcode.VCVTPS2DQ -> "vcvtps2dq"
    | Opcode.VCVTPS2PD -> "vcvtps2pd"
    | Opcode.VCVTPS2PH -> "vcvtps2ph"
    | Opcode.VCVTPS2PHX -> "vcvtps2phx"
    | Opcode.VCVTPS2QQ -> "vcvtps2qq"
    | Opcode.VCVTPS2UDQ -> "vcvtps2udq"
    | Opcode.VCVTPS2UQQ -> "vcvtps2uqq"
    | Opcode.VCVTQQ2PD -> "vcvtqq2pd"
    | Opcode.VCVTQQ2PH -> "vcvtqq2ph"
    | Opcode.VCVTQQ2PS -> "vcvtqq2ps"
    | Opcode.VCVTSD2SH -> "vcvtsd2sh"
    | Opcode.VCVTSD2SI -> "vcvtsd2si"
    | Opcode.VCVTSD2SS -> "vcvtsd2ss"
    | Opcode.VCVTSD2USI -> "vcvtsd2usi"
    | Opcode.VCVTSH2SD -> "vcvtsh2sd"
    | Opcode.VCVTSH2SI -> "vcvtsh2si"
    | Opcode.VCVTSH2SS -> "vcvtsh2ss"
    | Opcode.VCVTSH2USI -> "vcvtsh2usi"
    | Opcode.VCVTSI2SD -> "vcvtsi2sd"
    | Opcode.VCVTSI2SH -> "vcvtsi2sh"
    | Opcode.VCVTSI2SS -> "vcvtsi2ss"
    | Opcode.VCVTSS2SD -> "vcvtss2sd"
    | Opcode.VCVTSS2SH -> "vcvtss2sh"
    | Opcode.VCVTSS2SI -> "vcvtss2si"
    | Opcode.VCVTSS2USI -> "vcvtss2usi"
    | Opcode.VCVTTPD2DQ -> "vcvttpd2dq"
    | Opcode.VCVTTPD2QQ -> "vcvttpd2qq"
    | Opcode.VCVTTPD2UDQ -> "vcvttpd2udq"
    | Opcode.VCVTTPD2UQQ -> "vcvttpd2uqq"
    | Opcode.VCVTTPH2DQ -> "vcvttph2dq"
    | Opcode.VCVTTPH2QQ -> "vcvttph2qq"
    | Opcode.VCVTTPH2UDQ -> "vcvttph2udq"
    | Opcode.VCVTTPH2UQQ -> "vcvttph2uqq"
    | Opcode.VCVTTPH2UW -> "vcvttph2uw"
    | Opcode.VCVTTPH2W -> "vcvttph2w"
    | Opcode.VCVTTPS2DQ -> "vcvttps2dq"
    | Opcode.VCVTTPS2QQ -> "vcvttps2qq"
    | Opcode.VCVTTPS2UDQ -> "vcvttps2udq"
    | Opcode.VCVTTPS2UQQ -> "vcvttps2uqq"
    | Opcode.VCVTTSD2SI -> "vcvttsd2si"
    | Opcode.VCVTTSD2USI -> "vcvttsd2usi"
    | Opcode.VCVTTSH2SI -> "vcvttsh2si"
    | Opcode.VCVTTSH2USI -> "vcvttsh2usi"
    | Opcode.VCVTTSS2SI -> "vcvttss2si"
    | Opcode.VCVTTSS2USI -> "vcvttss2usi"
    | Opcode.VCVTUDQ2PD -> "vcvtudq2pd"
    | Opcode.VCVTUDQ2PH -> "vcvtudq2ph"
    | Opcode.VCVTUDQ2PS -> "vcvtudq2ps"
    | Opcode.VCVTUQQ2PD -> "vcvtuqq2pd"
    | Opcode.VCVTUQQ2PH -> "vcvtuqq2ph"
    | Opcode.VCVTUQQ2PS -> "vcvtuqq2ps"
    | Opcode.VCVTUSI2SD -> "vcvtusi2sd"
    | Opcode.VCVTUSI2SH -> "vcvtusi2sh"
    | Opcode.VCVTUSI2SS -> "vcvtusi2ss"
    | Opcode.VCVTUW2PH -> "vcvtuw2ph"
    | Opcode.VCVTW2PH -> "vcvtw2ph"
    | Opcode.VDBPSADBW -> "vdbpsadbw"
    | Opcode.VDIVPD -> "vdivpd"
    | Opcode.VDIVPH -> "vdivph"
    | Opcode.VDIVPS -> "vdivps"
    | Opcode.VDIVSD -> "vdivsd"
    | Opcode.VDIVSH -> "vdivsh"
    | Opcode.VDIVSS -> "vdivss"
    | Opcode.VDPBF16PS -> "vdpbf16ps"
    | Opcode.VDPPD -> "vdppd"
    | Opcode.VDPPS -> "vdpps"
    | Opcode.VERR -> "verr"
    | Opcode.VERW -> "verw"
    | Opcode.VEXP2PD -> "vexp2pd"
    | Opcode.VEXP2PS -> "vexp2ps"
    | Opcode.VEXPANDPD -> "vexpandpd"
    | Opcode.VEXPANDPS -> "vexpandps"
    | Opcode.VEXTRACTF128 -> "vextractf128"
    | Opcode.VEXTRACTF32X4 -> "vextractf32x4"
    | Opcode.VEXTRACTF32X8 -> "vextractf32x8"
    | Opcode.VEXTRACTF64X2 -> "vextractf64x2"
    | Opcode.VEXTRACTF64X4 -> "vextractf64x4"
    | Opcode.VEXTRACTI128 -> "vextracti128"
    | Opcode.VEXTRACTI32X4 -> "vextracti32x4"
    | Opcode.VEXTRACTI32X8 -> "vextracti32x8"
    | Opcode.VEXTRACTI64X2 -> "vextracti64x2"
    | Opcode.VEXTRACTI64X4 -> "vextracti64x4"
    | Opcode.VEXTRACTPS -> "vextractps"
    | Opcode.VFCMADDCPH -> "vfcmaddcph"
    | Opcode.VFCMADDCSH -> "vfcmaddcsh"
    | Opcode.VFCMULCPH -> "vfcmulcph"
    | Opcode.VFCMULCSH -> "vfcmulcsh"
    | Opcode.VFIXUPIMMPD -> "vfixupimmpd"
    | Opcode.VFIXUPIMMPS -> "vfixupimmps"
    | Opcode.VFIXUPIMMSD -> "vfixupimmsd"
    | Opcode.VFIXUPIMMSS -> "vfixupimmss"
    | Opcode.VFMADD132PD -> "vfmadd132pd"
    | Opcode.VFMADD132PH -> "vfmadd132ph"
    | Opcode.VFMADD132PS -> "vfmadd132ps"
    | Opcode.VFMADD132SD -> "vfmadd132sd"
    | Opcode.VFMADD132SH -> "vfmadd132sh"
    | Opcode.VFMADD132SS -> "vfmadd132ss"
    | Opcode.VFMADD213PD -> "vfmadd213pd"
    | Opcode.VFMADD213PH -> "vfmadd213ph"
    | Opcode.VFMADD213PS -> "vfmadd213ps"
    | Opcode.VFMADD213SD -> "vfmadd213sd"
    | Opcode.VFMADD213SH -> "vfmadd213sh"
    | Opcode.VFMADD213SS -> "vfmadd213ss"
    | Opcode.VFMADD231PD -> "vfmadd231pd"
    | Opcode.VFMADD231PH -> "vfmadd231ph"
    | Opcode.VFMADD231PS -> "vfmadd231ps"
    | Opcode.VFMADD231SD -> "vfmadd231sd"
    | Opcode.VFMADD231SH -> "vfmadd231sh"
    | Opcode.VFMADD231SS -> "vfmadd231ss"
    | Opcode.VFMADDCPH -> "vfmaddcph"
    | Opcode.VFMADDCSH -> "vfmaddcsh"
    | Opcode.VFMADDPD -> "vfmaddpd"
    | Opcode.VFMADDPS -> "vfmaddps"
    | Opcode.VFMADDSD -> "vfmaddsd"
    | Opcode.VFMADDSS -> "vfmaddss"
    | Opcode.VFMADDSUB132PD -> "vfmaddsub132pd"
    | Opcode.VFMADDSUB132PH -> "vfmaddsub132ph"
    | Opcode.VFMADDSUB132PS -> "vfmaddsub132ps"
    | Opcode.VFMADDSUB213PD -> "vfmaddsub213pd"
    | Opcode.VFMADDSUB213PH -> "vfmaddsub213ph"
    | Opcode.VFMADDSUB213PS -> "vfmaddsub213ps"
    | Opcode.VFMADDSUB231PD -> "vfmaddsub231pd"
    | Opcode.VFMADDSUB231PH -> "vfmaddsub231ph"
    | Opcode.VFMADDSUB231PS -> "vfmaddsub231ps"
    | Opcode.VFMSUB132PD -> "vfmsub132pd"
    | Opcode.VFMSUB132PH -> "vfmsub132ph"
    | Opcode.VFMSUB132PS -> "vfmsub132ps"
    | Opcode.VFMSUB132SD -> "vfmsub132sd"
    | Opcode.VFMSUB132SH -> "vfmsub132sh"
    | Opcode.VFMSUB132SS -> "vfmsub132ss"
    | Opcode.VFMSUB213PD -> "vfmsub213pd"
    | Opcode.VFMSUB213PH -> "vfmsub213ph"
    | Opcode.VFMSUB213PS -> "vfmsub213ps"
    | Opcode.VFMSUB213SD -> "vfmsub213sd"
    | Opcode.VFMSUB213SH -> "vfmsub213sh"
    | Opcode.VFMSUB213SS -> "vfmsub213ss"
    | Opcode.VFMSUB231PD -> "vfmsub231pd"
    | Opcode.VFMSUB231PH -> "vfmsub231ph"
    | Opcode.VFMSUB231PS -> "vfmsub231ps"
    | Opcode.VFMSUB231SD -> "vfmsub231sd"
    | Opcode.VFMSUB231SH -> "vfmsub231sh"
    | Opcode.VFMSUB231SS -> "vfmsub231ss"
    | Opcode.VFMSUBADD132PD -> "vfmsubadd132pd"
    | Opcode.VFMSUBADD132PH -> "vfmsubadd132ph"
    | Opcode.VFMSUBADD132PS -> "vfmsubadd132ps"
    | Opcode.VFMSUBADD213PD -> "vfmsubadd213pd"
    | Opcode.VFMSUBADD213PH -> "vfmsubadd213ph"
    | Opcode.VFMSUBADD213PS -> "vfmsubadd213ps"
    | Opcode.VFMSUBADD231PD -> "vfmsubadd231pd"
    | Opcode.VFMSUBADD231PH -> "vfmsubadd231ph"
    | Opcode.VFMSUBADD231PS -> "vfmsubadd231ps"
    | Opcode.VFMULCPH -> "vfmulcph"
    | Opcode.VFMULCSH -> "vfmulcsh"
    | Opcode.VFNMADD132PD -> "vfnmadd132pd"
    | Opcode.VFNMADD132PH -> "vfnmadd132ph"
    | Opcode.VFNMADD132PS -> "vfnmadd132ps"
    | Opcode.VFNMADD132SD -> "vfnmadd132sd"
    | Opcode.VFNMADD132SH -> "vfnmadd132sh"
    | Opcode.VFNMADD132SS -> "vfnmadd132ss"
    | Opcode.VFNMADD213PD -> "vfnmadd213pd"
    | Opcode.VFNMADD213PH -> "vfnmadd213ph"
    | Opcode.VFNMADD213PS -> "vfnmadd213ps"
    | Opcode.VFNMADD213SD -> "vfnmadd213sd"
    | Opcode.VFNMADD213SH -> "vfnmadd213sh"
    | Opcode.VFNMADD213SS -> "vfnmadd213ss"
    | Opcode.VFNMADD231PD -> "vfnmadd231pd"
    | Opcode.VFNMADD231PH -> "vfnmadd231ph"
    | Opcode.VFNMADD231PS -> "vfnmadd231ps"
    | Opcode.VFNMADD231SD -> "vfnmadd231sd"
    | Opcode.VFNMADD231SH -> "vfnmadd231sh"
    | Opcode.VFNMADD231SS -> "vfnmadd231ss"
    | Opcode.VFNMSUB132PD -> "vfnmsub132pd"
    | Opcode.VFNMSUB132PH -> "vfnmsub132ph"
    | Opcode.VFNMSUB132PS -> "vfnmsub132ps"
    | Opcode.VFNMSUB132SD -> "vfnmsub132sd"
    | Opcode.VFNMSUB132SH -> "vfnmsub132sh"
    | Opcode.VFNMSUB132SS -> "vfnmsub132ss"
    | Opcode.VFNMSUB213PD -> "vfnmsub213pd"
    | Opcode.VFNMSUB213PH -> "vfnmsub213ph"
    | Opcode.VFNMSUB213PS -> "vfnmsub213ps"
    | Opcode.VFNMSUB213SD -> "vfnmsub213sd"
    | Opcode.VFNMSUB213SH -> "vfnmsub213sh"
    | Opcode.VFNMSUB213SS -> "vfnmsub213ss"
    | Opcode.VFNMSUB231PD -> "vfnmsub231pd"
    | Opcode.VFNMSUB231PH -> "vfnmsub231ph"
    | Opcode.VFNMSUB231PS -> "vfnmsub231ps"
    | Opcode.VFNMSUB231SD -> "vfnmsub231sd"
    | Opcode.VFNMSUB231SH -> "vfnmsub231sh"
    | Opcode.VFNMSUB231SS -> "vfnmsub231ss"
    | Opcode.VFPCLASSPD -> "vfpclasspd"
    | Opcode.VFPCLASSPH -> "vfpclassph"
    | Opcode.VFPCLASSPS -> "vfpclassps"
    | Opcode.VFPCLASSSD -> "vfpclasssd"
    | Opcode.VFPCLASSSH -> "vfpclasssh"
    | Opcode.VFPCLASSSS -> "vfpclassss"
    | Opcode.VGATHERDPD -> "vgatherdpd"
    | Opcode.VGATHERDPS -> "vgatherdps"
    | Opcode.VGATHERPF0DPD -> "vgatherpf0dpd"
    | Opcode.VGATHERPF0DPS -> "vgatherpf0dps"
    | Opcode.VGATHERPF0QPD -> "vgatherpf0qpd"
    | Opcode.VGATHERPF0QPS -> "vgatherpf0qps"
    | Opcode.VGATHERPF1DPD -> "vgatherpf1dpd"
    | Opcode.VGATHERPF1DPS -> "vgatherpf1dps"
    | Opcode.VGATHERPF1QPD -> "vgatherpf1qpd"
    | Opcode.VGATHERPF1QPS -> "vgatherpf1qps"
    | Opcode.VGATHERQPD -> "vgatherqpd"
    | Opcode.VGATHERQPS -> "vgatherqps"
    | Opcode.VGETEXPPD -> "vgetexppd"
    | Opcode.VGETEXPPH -> "vgetexpph"
    | Opcode.VGETEXPPS -> "vgetexpps"
    | Opcode.VGETEXPSD -> "vgetexpsd"
    | Opcode.VGETEXPSH -> "vgetexpsh"
    | Opcode.VGETEXPSS -> "vgetexpss"
    | Opcode.VGETMANTPD -> "vgetmantpd"
    | Opcode.VGETMANTPH -> "vgetmantph"
    | Opcode.VGETMANTPS -> "vgetmantps"
    | Opcode.VGETMANTSD -> "vgetmantsd"
    | Opcode.VGETMANTSH -> "vgetmantsh"
    | Opcode.VGETMANTSS -> "vgetmantss"
    | Opcode.VGF2P8AFFINEINVQB -> "vgf2p8affineinvqb"
    | Opcode.VGF2P8AFFINEQB -> "vgf2p8affineqb"
    | Opcode.VGF2P8MULB -> "vgf2p8mulb"
    | Opcode.VHADDPD -> "vhaddpd"
    | Opcode.VHADDPS -> "vhaddps"
    | Opcode.VHSUBPD -> "vhsubpd"
    | Opcode.VHSUBPS -> "vhsubps"
    | Opcode.VINSERTF128 -> "vinsertf128"
    | Opcode.VINSERTF32X4 -> "vinsertf32x4"
    | Opcode.VINSERTF32X8 -> "vinsertf32x8"
    | Opcode.VINSERTF64X2 -> "vinsertf64x2"
    | Opcode.VINSERTF64X4 -> "vinsertf64x4"
    | Opcode.VINSERTI128 -> "vinserti128"
    | Opcode.VINSERTI32X4 -> "vinserti32x4"
    | Opcode.VINSERTI32X8 -> "vinserti32x8"
    | Opcode.VINSERTI64X2 -> "vinserti64x2"
    | Opcode.VINSERTI64X4 -> "vinserti64x4"
    | Opcode.VINSERTPS -> "vinsertps"
    | Opcode.VLDDQU -> "vlddqu"
    | Opcode.VLDMXCSR -> "vldmxcsr"
    | Opcode.VMASKMOVDQU -> "vmaskmovdqu"
    | Opcode.VMASKMOVPD -> "vmaskmovpd"
    | Opcode.VMASKMOVPS -> "vmaskmovps"
    | Opcode.VMAXPD -> "vmaxpd"
    | Opcode.VMAXPH -> "vmaxph"
    | Opcode.VMAXPS -> "vmaxps"
    | Opcode.VMAXSD -> "vmaxsd"
    | Opcode.VMAXSH -> "vmaxsh"
    | Opcode.VMAXSS -> "vmaxss"
    | Opcode.VMCALL -> "vmcall"
    | Opcode.VMCLEAR -> "vmclear"
    | Opcode.VMFUNC -> "vmfunc"
    | Opcode.VMINPD -> "vminpd"
    | Opcode.VMINPH -> "vminph"
    | Opcode.VMINPS -> "vminps"
    | Opcode.VMINSD -> "vminsd"
    | Opcode.VMINSH -> "vminsh"
    | Opcode.VMINSS -> "vminss"
    | Opcode.VMLAUNCH -> "vmlaunch"
    | Opcode.VMOVAPD -> "vmovapd"
    | Opcode.VMOVAPS -> "vmovaps"
    | Opcode.VMOVD -> "vmovd"
    | Opcode.VMOVDDUP -> "vmovddup"
    | Opcode.VMOVDQA -> "vmovdqa"
    | Opcode.VMOVDQA32 -> "vmovdqa32"
    | Opcode.VMOVDQA64 -> "vmovdqa64"
    | Opcode.VMOVDQU -> "vmovdqu"
    | Opcode.VMOVDQU16 -> "vmovdqu16"
    | Opcode.VMOVDQU32 -> "vmovdqu32"
    | Opcode.VMOVDQU64 -> "vmovdqu64"
    | Opcode.VMOVDQU8 -> "vmovdqu8"
    | Opcode.VMOVHLPS -> "vmovhlps"
    | Opcode.VMOVHPD -> "vmovhpd"
    | Opcode.VMOVHPS -> "vmovhps"
    | Opcode.VMOVLHPS -> "vmovlhps"
    | Opcode.VMOVLPD -> "vmovlpd"
    | Opcode.VMOVLPS -> "vmovlps"
    | Opcode.VMOVMSKPD -> "vmovmskpd"
    | Opcode.VMOVMSKPS -> "vmovmskps"
    | Opcode.VMOVNTDQ -> "vmovntdq"
    | Opcode.VMOVNTDQA -> "vmovntdqa"
    | Opcode.VMOVNTPD -> "vmovntpd"
    | Opcode.VMOVNTPS -> "vmovntps"
    | Opcode.VMOVQ -> "vmovq"
    | Opcode.VMOVSD -> "vmovsd"
    | Opcode.VMOVSH -> "vmovsh"
    | Opcode.VMOVSHDUP -> "vmovshdup"
    | Opcode.VMOVSLDUP -> "vmovsldup"
    | Opcode.VMOVSS -> "vmovss"
    | Opcode.VMOVUPD -> "vmovupd"
    | Opcode.VMOVUPS -> "vmovups"
    | Opcode.VMOVW -> "vmovw"
    | Opcode.VMPSADBW -> "vmpsadbw"
    | Opcode.VMPTRLD -> "vmptrld"
    | Opcode.VMPTRST -> "vmptrst"
    | Opcode.VMREAD -> "vmread"
    | Opcode.VMRESUME -> "vmresume"
    | Opcode.VMULPD -> "vmulpd"
    | Opcode.VMULPH -> "vmulph"
    | Opcode.VMULPS -> "vmulps"
    | Opcode.VMULSD -> "vmulsd"
    | Opcode.VMULSH -> "vmulsh"
    | Opcode.VMULSS -> "vmulss"
    | Opcode.VMXOFF -> "vmxoff"
    | Opcode.VMXON -> "vmxon"
    | Opcode.VORPD -> "vorpd"
    | Opcode.VORPS -> "vorps"
    | Opcode.VP2INTERSECTD -> "vp2intersectd"
    | Opcode.VP2INTERSECTQ -> "vp2intersectq"
    | Opcode.VP4DPWSSD -> "vp4dpwssd"
    | Opcode.VP4DPWSSDS -> "vp4dpwssds"
    | Opcode.VPABSB -> "vpabsb"
    | Opcode.VPABSD -> "vpabsd"
    | Opcode.VPABSQ -> "vpabsq"
    | Opcode.VPABSW -> "vpabsw"
    | Opcode.VPACKSSDW -> "vpackssdw"
    | Opcode.VPACKSSWB -> "vpacksswb"
    | Opcode.VPACKUSDW -> "vpackusdw"
    | Opcode.VPACKUSWB -> "vpackuswb"
    | Opcode.VPADDB -> "vpaddb"
    | Opcode.VPADDD -> "vpaddd"
    | Opcode.VPADDQ -> "vpaddq"
    | Opcode.VPADDSB -> "vpaddsb"
    | Opcode.VPADDSW -> "vpaddsw"
    | Opcode.VPADDUSB -> "vpaddusb"
    | Opcode.VPADDUSW -> "vpaddusw"
    | Opcode.VPADDW -> "vpaddw"
    | Opcode.VPALIGNR -> "vpalignr"
    | Opcode.VPAND -> "vpand"
    | Opcode.VPANDD -> "vpandd"
    | Opcode.VPANDN -> "vpandn"
    | Opcode.VPANDND -> "vpandnd"
    | Opcode.VPANDNQ -> "vpandnq"
    | Opcode.VPANDQ -> "vpandq"
    | Opcode.VPAVGB -> "vpavgb"
    | Opcode.VPAVGW -> "vpavgw"
    | Opcode.VPBLENDD -> "vpblendd"
    | Opcode.VPBLENDMB -> "vpblendmb"
    | Opcode.VPBLENDMD -> "vpblendmd"
    | Opcode.VPBLENDMQ -> "vpblendmq"
    | Opcode.VPBLENDMW -> "vpblendmw"
    | Opcode.VPBLENDVB -> "vpblendvb"
    | Opcode.VPBLENDW -> "vpblendw"
    | Opcode.VPBROADCASTB -> "vpbroadcastb"
    | Opcode.VPBROADCASTD -> "vpbroadcastd"
    | Opcode.VPBROADCASTMB2Q -> "vpbroadcastmb2q"
    | Opcode.VPBROADCASTMW2D -> "vpbroadcastmw2d"
    | Opcode.VPBROADCASTQ -> "vpbroadcastq"
    | Opcode.VPBROADCASTW -> "vpbroadcastw"
    | Opcode.VPCLMULQDQ -> "vpclmulqdq"
    | Opcode.VPCMPB -> "vpcmpb"
    | Opcode.VPCMPD -> "vpcmpd"
    | Opcode.VPCMPEQB -> "vpcmpeqb"
    | Opcode.VPCMPEQD -> "vpcmpeqd"
    | Opcode.VPCMPEQQ -> "vpcmpeqq"
    | Opcode.VPCMPEQW -> "vpcmpeqw"
    | Opcode.VPCMPESTRI -> "vpcmpestri"
    | Opcode.VPCMPESTRM -> "vpcmpestrm"
    | Opcode.VPCMPGTB -> "vpcmpgtb"
    | Opcode.VPCMPGTD -> "vpcmpgtd"
    | Opcode.VPCMPGTQ -> "vpcmpgtq"
    | Opcode.VPCMPGTW -> "vpcmpgtw"
    | Opcode.VPCMPISTRI -> "vpcmpistri"
    | Opcode.VPCMPISTRM -> "vpcmpistrm"
    | Opcode.VPCMPQ -> "vpcmpq"
    | Opcode.VPCMPUB -> "vpcmpub"
    | Opcode.VPCMPUD -> "vpcmpud"
    | Opcode.VPCMPUQ -> "vpcmpuq"
    | Opcode.VPCMPUW -> "vpcmpuw"
    | Opcode.VPCMPW -> "vpcmpw"
    | Opcode.VPCOMPRESSB -> "vpcompressb"
    | Opcode.VPCOMPRESSD -> "vpcompressd"
    | Opcode.VPCOMPRESSQ -> "vpcompressq"
    | Opcode.VPCOMPRESSW -> "vpcompressw"
    | Opcode.VPCONFLICTD -> "vpconflictd"
    | Opcode.VPCONFLICTQ -> "vpconflictq"
    | Opcode.VPDPBSSD -> "vpdpbssd"
    | Opcode.VPDPBSSDS -> "vpdpbssds"
    | Opcode.VPDPBSUD -> "vpdpbsud"
    | Opcode.VPDPBSUDS -> "vpdpbsuds"
    | Opcode.VPDPBUSD -> "vpdpbusd"
    | Opcode.VPDPBUSDS -> "vpdpbusds"
    | Opcode.VPDPBUUD -> "vpdpbuud"
    | Opcode.VPDPBUUDS -> "vpdpbuuds"
    | Opcode.VPDPWSSD -> "vpdpwssd"
    | Opcode.VPDPWSSDS -> "vpdpwssds"
    | Opcode.VPDPWSUD -> "vpdpwsud"
    | Opcode.VPDPWSUDS -> "vpdpwsuds"
    | Opcode.VPDPWUSD -> "vpdpwusd"
    | Opcode.VPDPWUSDS -> "vpdpwusds"
    | Opcode.VPDPWUUD -> "vpdpwuud"
    | Opcode.VPDPWUUDS -> "vpdpwuuds"
    | Opcode.VPERM2F128 -> "vperm2f128"
    | Opcode.VPERM2I128 -> "vperm2i128"
    | Opcode.VPERMB -> "vpermb"
    | Opcode.VPERMD -> "vpermd"
    | Opcode.VPERMI2B -> "vpermi2b"
    | Opcode.VPERMI2D -> "vpermi2d"
    | Opcode.VPERMI2PD -> "vpermi2pd"
    | Opcode.VPERMI2PS -> "vpermi2ps"
    | Opcode.VPERMI2Q -> "vpermi2q"
    | Opcode.VPERMI2W -> "vpermi2w"
    | Opcode.VPERMILPD -> "vpermilpd"
    | Opcode.VPERMILPS -> "vpermilps"
    | Opcode.VPERMPD -> "vpermpd"
    | Opcode.VPERMPS -> "vpermps"
    | Opcode.VPERMQ -> "vpermq"
    | Opcode.VPERMT2B -> "vpermt2b"
    | Opcode.VPERMT2D -> "vpermt2d"
    | Opcode.VPERMT2PD -> "vpermt2pd"
    | Opcode.VPERMT2PS -> "vpermt2ps"
    | Opcode.VPERMT2Q -> "vpermt2q"
    | Opcode.VPERMT2W -> "vpermt2w"
    | Opcode.VPERMW -> "vpermw"
    | Opcode.VPEXPANDB -> "vpexpandb"
    | Opcode.VPEXPANDD -> "vpexpandd"
    | Opcode.VPEXPANDQ -> "vpexpandq"
    | Opcode.VPEXPANDW -> "vpexpandw"
    | Opcode.VPEXTRB -> "vpextrb"
    | Opcode.VPEXTRD -> "vpextrd"
    | Opcode.VPEXTRQ -> "vpextrq"
    | Opcode.VPEXTRW -> "vpextrw"
    | Opcode.VPGATHERDD -> "vpgatherdd"
    | Opcode.VPGATHERDQ -> "vpgatherdq"
    | Opcode.VPGATHERQD -> "vpgatherqd"
    | Opcode.VPGATHERQQ -> "vpgatherqq"
    | Opcode.VPHADDD -> "vphaddd"
    | Opcode.VPHADDSW -> "vphaddsw"
    | Opcode.VPHADDW -> "vphaddw"
    | Opcode.VPHMINPOSUW -> "vphminposuw"
    | Opcode.VPHSUBD -> "vphsubd"
    | Opcode.VPHSUBSW -> "vphsubsw"
    | Opcode.VPHSUBW -> "vphsubw"
    | Opcode.VPINSRB -> "vpinsrb"
    | Opcode.VPINSRD -> "vpinsrd"
    | Opcode.VPINSRQ -> "vpinsrq"
    | Opcode.VPINSRW -> "vpinsrw"
    | Opcode.VPLZCNTD -> "vplzcntd"
    | Opcode.VPLZCNTQ -> "vplzcntq"
    | Opcode.VPMADD52HUQ -> "vpmadd52huq"
    | Opcode.VPMADD52LUQ -> "vpmadd52luq"
    | Opcode.VPMADDUBSW -> "vpmaddubsw"
    | Opcode.VPMADDWD -> "vpmaddwd"
    | Opcode.VPMASKMOVD -> "vpmaskmovd"
    | Opcode.VPMASKMOVQ -> "vpmaskmovq"
    | Opcode.VPMAXSB -> "vpmaxsb"
    | Opcode.VPMAXSD -> "vpmaxsd"
    | Opcode.VPMAXSQ -> "vpmaxsq"
    | Opcode.VPMAXSW -> "vpmaxsw"
    | Opcode.VPMAXUB -> "vpmaxub"
    | Opcode.VPMAXUD -> "vpmaxud"
    | Opcode.VPMAXUQ -> "vpmaxuq"
    | Opcode.VPMAXUW -> "vpmaxuw"
    | Opcode.VPMINSB -> "vpminsb"
    | Opcode.VPMINSD -> "vpminsd"
    | Opcode.VPMINSQ -> "vpminsq"
    | Opcode.VPMINSW -> "vpminsw"
    | Opcode.VPMINUB -> "vpminub"
    | Opcode.VPMINUD -> "vpminud"
    | Opcode.VPMINUQ -> "vpminuq"
    | Opcode.VPMINUW -> "vpminuw"
    | Opcode.VPMOVB2M -> "vpmovb2m"
    | Opcode.VPMOVD2M -> "vpmovd2m"
    | Opcode.VPMOVDB -> "vpmovdb"
    | Opcode.VPMOVDW -> "vpmovdw"
    | Opcode.VPMOVM2B -> "vpmovm2b"
    | Opcode.VPMOVM2D -> "vpmovm2d"
    | Opcode.VPMOVM2Q -> "vpmovm2q"
    | Opcode.VPMOVM2W -> "vpmovm2w"
    | Opcode.VPMOVMSKB -> "vpmovmskb"
    | Opcode.VPMOVQ2M -> "vpmovq2m"
    | Opcode.VPMOVQB -> "vpmovqb"
    | Opcode.VPMOVQD -> "vpmovqd"
    | Opcode.VPMOVQW -> "vpmovqw"
    | Opcode.VPMOVSDB -> "vpmovsdb"
    | Opcode.VPMOVSDW -> "vpmovsdw"
    | Opcode.VPMOVSQB -> "vpmovsqb"
    | Opcode.VPMOVSQD -> "vpmovsqd"
    | Opcode.VPMOVSQW -> "vpmovsqw"
    | Opcode.VPMOVSWB -> "vpmovswb"
    | Opcode.VPMOVSXBD -> "vpmovsxbd"
    | Opcode.VPMOVSXBQ -> "vpmovsxbq"
    | Opcode.VPMOVSXBW -> "vpmovsxbw"
    | Opcode.VPMOVSXDQ -> "vpmovsxdq"
    | Opcode.VPMOVSXWD -> "vpmovsxwd"
    | Opcode.VPMOVSXWQ -> "vpmovsxwq"
    | Opcode.VPMOVUSDB -> "vpmovusdb"
    | Opcode.VPMOVUSDW -> "vpmovusdw"
    | Opcode.VPMOVUSQB -> "vpmovusqb"
    | Opcode.VPMOVUSQD -> "vpmovusqd"
    | Opcode.VPMOVUSQW -> "vpmovusqw"
    | Opcode.VPMOVUSWB -> "vpmovuswb"
    | Opcode.VPMOVW2M -> "vpmovw2m"
    | Opcode.VPMOVWB -> "vpmovwb"
    | Opcode.VPMOVZXBD -> "vpmovzxbd"
    | Opcode.VPMOVZXBQ -> "vpmovzxbq"
    | Opcode.VPMOVZXBW -> "vpmovzxbw"
    | Opcode.VPMOVZXDQ -> "vpmovzxdq"
    | Opcode.VPMOVZXWD -> "vpmovzxwd"
    | Opcode.VPMOVZXWQ -> "vpmovzxwq"
    | Opcode.VPMULDQ -> "vpmuldq"
    | Opcode.VPMULHRSW -> "vpmulhrsw"
    | Opcode.VPMULHUW -> "vpmulhuw"
    | Opcode.VPMULHW -> "vpmulhw"
    | Opcode.VPMULLD -> "vpmulld"
    | Opcode.VPMULLQ -> "vpmullq"
    | Opcode.VPMULLW -> "vpmullw"
    | Opcode.VPMULTISHIFTQB -> "vpmultishiftqb"
    | Opcode.VPMULUDQ -> "vpmuludq"
    | Opcode.VPOPCNTB -> "vpopcntb"
    | Opcode.VPOPCNTD -> "vpopcntd"
    | Opcode.VPOPCNTQ -> "vpopcntq"
    | Opcode.VPOPCNTW -> "vpopcntw"
    | Opcode.VPOR -> "vpor"
    | Opcode.VPORD -> "vpord"
    | Opcode.VPORQ -> "vporq"
    | Opcode.VPROLD -> "vprold"
    | Opcode.VPROLQ -> "vprolq"
    | Opcode.VPROLVD -> "vprolvd"
    | Opcode.VPROLVQ -> "vprolvq"
    | Opcode.VPRORD -> "vprord"
    | Opcode.VPRORQ -> "vprorq"
    | Opcode.VPRORVD -> "vprorvd"
    | Opcode.VPRORVQ -> "vprorvq"
    | Opcode.VPSADBW -> "vpsadbw"
    | Opcode.VPSCATTERDD -> "vpscatterdd"
    | Opcode.VPSCATTERDQ -> "vpscatterdq"
    | Opcode.VPSCATTERQD -> "vpscatterqd"
    | Opcode.VPSCATTERQQ -> "vpscatterqq"
    | Opcode.VPSHLDD -> "vpshldd"
    | Opcode.VPSHLDQ -> "vpshldq"
    | Opcode.VPSHLDVD -> "vpshldvd"
    | Opcode.VPSHLDVQ -> "vpshldvq"
    | Opcode.VPSHLDVW -> "vpshldvw"
    | Opcode.VPSHLDW -> "vpshldw"
    | Opcode.VPSHRDD -> "vpshrdd"
    | Opcode.VPSHRDQ -> "vpshrdq"
    | Opcode.VPSHRDVD -> "vpshrdvd"
    | Opcode.VPSHRDVQ -> "vpshrdvq"
    | Opcode.VPSHRDVW -> "vpshrdvw"
    | Opcode.VPSHRDW -> "vpshrdw"
    | Opcode.VPSHUFB -> "vpshufb"
    | Opcode.VPSHUFBITQMB -> "vpshufbitqmb"
    | Opcode.VPSHUFD -> "vpshufd"
    | Opcode.VPSHUFHW -> "vpshufhw"
    | Opcode.VPSHUFLW -> "vpshuflw"
    | Opcode.VPSIGNB -> "vpsignb"
    | Opcode.VPSIGND -> "vpsignd"
    | Opcode.VPSIGNW -> "vpsignw"
    | Opcode.VPSLLD -> "vpslld"
    | Opcode.VPSLLDQ -> "vpslldq"
    | Opcode.VPSLLQ -> "vpsllq"
    | Opcode.VPSLLVD -> "vpsllvd"
    | Opcode.VPSLLVQ -> "vpsllvq"
    | Opcode.VPSLLVW -> "vpsllvw"
    | Opcode.VPSLLW -> "vpsllw"
    | Opcode.VPSRAD -> "vpsrad"
    | Opcode.VPSRAQ -> "vpsraq"
    | Opcode.VPSRAVD -> "vpsravd"
    | Opcode.VPSRAVQ -> "vpsravq"
    | Opcode.VPSRAVW -> "vpsravw"
    | Opcode.VPSRAW -> "vpsraw"
    | Opcode.VPSRLD -> "vpsrld"
    | Opcode.VPSRLDQ -> "vpsrldq"
    | Opcode.VPSRLQ -> "vpsrlq"
    | Opcode.VPSRLVD -> "vpsrlvd"
    | Opcode.VPSRLVQ -> "vpsrlvq"
    | Opcode.VPSRLVW -> "vpsrlvw"
    | Opcode.VPSRLW -> "vpsrlw"
    | Opcode.VPSUBB -> "vpsubb"
    | Opcode.VPSUBD -> "vpsubd"
    | Opcode.VPSUBQ -> "vpsubq"
    | Opcode.VPSUBSB -> "vpsubsb"
    | Opcode.VPSUBSW -> "vpsubsw"
    | Opcode.VPSUBUSB -> "vpsubusb"
    | Opcode.VPSUBUSW -> "vpsubusw"
    | Opcode.VPSUBW -> "vpsubw"
    | Opcode.VPTERNLOGD -> "vpternlogd"
    | Opcode.VPTERNLOGQ -> "vpternlogq"
    | Opcode.VPTEST -> "vptest"
    | Opcode.VPTESTMB -> "vptestmb"
    | Opcode.VPTESTMD -> "vptestmd"
    | Opcode.VPTESTMQ -> "vptestmq"
    | Opcode.VPTESTMW -> "vptestmw"
    | Opcode.VPTESTNMB -> "vptestnmb"
    | Opcode.VPTESTNMD -> "vptestnmd"
    | Opcode.VPTESTNMQ -> "vptestnmq"
    | Opcode.VPTESTNMW -> "vptestnmw"
    | Opcode.VPUNPCKHBW -> "vpunpckhbw"
    | Opcode.VPUNPCKHDQ -> "vpunpckhdq"
    | Opcode.VPUNPCKHQDQ -> "vpunpckhqdq"
    | Opcode.VPUNPCKHWD -> "vpunpckhwd"
    | Opcode.VPUNPCKLBW -> "vpunpcklbw"
    | Opcode.VPUNPCKLDQ -> "vpunpckldq"
    | Opcode.VPUNPCKLQDQ -> "vpunpcklqdq"
    | Opcode.VPUNPCKLWD -> "vpunpcklwd"
    | Opcode.VPXOR -> "vpxor"
    | Opcode.VPXORD -> "vpxord"
    | Opcode.VPXORQ -> "vpxorq"
    | Opcode.VRANGEPD -> "vrangepd"
    | Opcode.VRANGEPS -> "vrangeps"
    | Opcode.VRANGESD -> "vrangesd"
    | Opcode.VRANGESS -> "vrangess"
    | Opcode.VRCP14PD -> "vrcp14pd"
    | Opcode.VRCP14PS -> "vrcp14ps"
    | Opcode.VRCP14SD -> "vrcp14sd"
    | Opcode.VRCP14SS -> "vrcp14ss"
    | Opcode.VRCP28PD -> "vrcp28pd"
    | Opcode.VRCP28PS -> "vrcp28ps"
    | Opcode.VRCP28SD -> "vrcp28sd"
    | Opcode.VRCP28SS -> "vrcp28ss"
    | Opcode.VRCPPH -> "vrcpph"
    | Opcode.VRCPPS -> "vrcpps"
    | Opcode.VRCPSH -> "vrcpsh"
    | Opcode.VRCPSS -> "vrcpss"
    | Opcode.VREDUCEPD -> "vreducepd"
    | Opcode.VREDUCEPH -> "vreduceph"
    | Opcode.VREDUCEPS -> "vreduceps"
    | Opcode.VREDUCESD -> "vreducesd"
    | Opcode.VREDUCESH -> "vreducesh"
    | Opcode.VREDUCESS -> "vreducess"
    | Opcode.VRNDSCALEPD -> "vrndscalepd"
    | Opcode.VRNDSCALEPH -> "vrndscaleph"
    | Opcode.VRNDSCALEPS -> "vrndscaleps"
    | Opcode.VRNDSCALESD -> "vrndscalesd"
    | Opcode.VRNDSCALESH -> "vrndscalesh"
    | Opcode.VRNDSCALESS -> "vrndscaless"
    | Opcode.VROUNDPD -> "vroundpd"
    | Opcode.VROUNDPS -> "vroundps"
    | Opcode.VROUNDSD -> "vroundsd"
    | Opcode.VROUNDSS -> "vroundss"
    | Opcode.VRSQRT14PD -> "vrsqrt14pd"
    | Opcode.VRSQRT14PS -> "vrsqrt14ps"
    | Opcode.VRSQRT14SD -> "vrsqrt14sd"
    | Opcode.VRSQRT14SS -> "vrsqrt14ss"
    | Opcode.VRSQRT28PD -> "vrsqrt28pd"
    | Opcode.VRSQRT28PS -> "vrsqrt28ps"
    | Opcode.VRSQRT28SD -> "vrsqrt28sd"
    | Opcode.VRSQRT28SS -> "vrsqrt28ss"
    | Opcode.VRSQRTPH -> "vrsqrtph"
    | Opcode.VRSQRTPS -> "vrsqrtps"
    | Opcode.VRSQRTSH -> "vrsqrtsh"
    | Opcode.VRSQRTSS -> "vrsqrtss"
    | Opcode.VSCALEFPD -> "vscalefpd"
    | Opcode.VSCALEFPH -> "vscalefph"
    | Opcode.VSCALEFPS -> "vscalefps"
    | Opcode.VSCALEFSD -> "vscalefsd"
    | Opcode.VSCALEFSH -> "vscalefsh"
    | Opcode.VSCALEFSS -> "vscalefss"
    | Opcode.VSCATTERDPD -> "vscatterdpd"
    | Opcode.VSCATTERDPS -> "vscatterdps"
    | Opcode.VSCATTERPF0DPD -> "vscatterpf0dpd"
    | Opcode.VSCATTERPF0DPS -> "vscatterpf0dps"
    | Opcode.VSCATTERPF0QPD -> "vscatterpf0qpd"
    | Opcode.VSCATTERPF0QPS -> "vscatterpf0qps"
    | Opcode.VSCATTERPF1DPD -> "vscatterpf1dpd"
    | Opcode.VSCATTERPF1DPS -> "vscatterpf1dps"
    | Opcode.VSCATTERPF1QPD -> "vscatterpf1qpd"
    | Opcode.VSCATTERPF1QPS -> "vscatterpf1qps"
    | Opcode.VSCATTERQPD -> "vscatterqpd"
    | Opcode.VSCATTERQPS -> "vscatterqps"
    | Opcode.VSHA512MSG1 -> "vsha512msg1"
    | Opcode.VSHA512MSG2 -> "vsha512msg2"
    | Opcode.VSHA512RNDS2 -> "vsha512rnds2"
    | Opcode.VSHUFF32X4 -> "vshuff32x4"
    | Opcode.VSHUFF64X2 -> "vshuff64x2"
    | Opcode.VSHUFI32X4 -> "vshufi32x4"
    | Opcode.VSHUFI64X2 -> "vshufi64x2"
    | Opcode.VSHUFPD -> "vshufpd"
    | Opcode.VSHUFPS -> "vshufps"
    | Opcode.VSM3MSG1 -> "vsm3msg1"
    | Opcode.VSM3MSG2 -> "vsm3msg2"
    | Opcode.VSM3RNDS2 -> "vsm3rnds2"
    | Opcode.VSM4KEY4 -> "vsm4key4"
    | Opcode.VSM4RNDS4 -> "vsm4rnds4"
    | Opcode.VSQRTPD -> "vsqrtpd"
    | Opcode.VSQRTPH -> "vsqrtph"
    | Opcode.VSQRTPS -> "vsqrtps"
    | Opcode.VSQRTSD -> "vsqrtsd"
    | Opcode.VSQRTSH -> "vsqrtsh"
    | Opcode.VSQRTSS -> "vsqrtss"
    | Opcode.VSTMXCSR -> "vstmxcsr"
    | Opcode.VSUBPD -> "vsubpd"
    | Opcode.VSUBPH -> "vsubph"
    | Opcode.VSUBPS -> "vsubps"
    | Opcode.VSUBSD -> "vsubsd"
    | Opcode.VSUBSH -> "vsubsh"
    | Opcode.VSUBSS -> "vsubss"
    | Opcode.VTESTPD -> "vtestpd"
    | Opcode.VTESTPS -> "vtestps"
    | Opcode.VUCOMISD -> "vucomisd"
    | Opcode.VUCOMISH -> "vucomish"
    | Opcode.VUCOMISS -> "vucomiss"
    | Opcode.VUNPCKHPD -> "vunpckhpd"
    | Opcode.VUNPCKHPS -> "vunpckhps"
    | Opcode.VUNPCKLPD -> "vunpcklpd"
    | Opcode.VUNPCKLPS -> "vunpcklps"
    | Opcode.VXORPD -> "vxorpd"
    | Opcode.VXORPS -> "vxorps"
    | Opcode.VZEROALL -> "vzeroall"
    | Opcode.VZEROUPPER -> "vzeroupper"
    | Opcode.WAIT -> "wait"
    | Opcode.WBINVD -> "wbinvd"
    | Opcode.WBNOINVD -> "wbnoinvd"
    | Opcode.WRFSBASE -> "wrfsbase"
    | Opcode.WRGSBASE -> "wrgsbase"
    | Opcode.WRMSR -> "wrmsr"
    | Opcode.WRMSRLIST -> "wrmsrlist"
    | Opcode.WRMSRNS -> "wrmsrns"
    | Opcode.WRPKRU -> "wrpkru"
    | Opcode.WRSSD -> "wrssd"
    | Opcode.WRSSQ -> "wrssq"
    | Opcode.WRUSSD -> "wrussd"
    | Opcode.WRUSSQ -> "wrussq"
    | Opcode.XABORT -> "xabort"
    | Opcode.XACQUIRE -> "xacquire"
    | Opcode.XADD -> "xadd"
    | Opcode.XBEGIN -> "xbegin"
    | Opcode.XCHG -> "xchg"
    | Opcode.XCRYPTCBC -> "xcryptcbc"
    | Opcode.XCRYPTCFB -> "xcryptcfb"
    | Opcode.XCRYPTCTR -> "xcryptctr"
    | Opcode.XCRYPTECB -> "xcryptecb"
    | Opcode.XCRYPTOFB -> "xcryptofb"
    | Opcode.XEND -> "xend"
    | Opcode.XGETBV -> "xgetbv"
    | Opcode.XLAT -> "xlat"
    | Opcode.XLATB -> "xlatb"
    | Opcode.XMODEXP -> "xmodexp"
    | Opcode.XOR -> "xor"
    | Opcode.XORPD -> "xorpd"
    | Opcode.XORPS -> "xorps"
    | Opcode.XRELEASE -> "xrelease"
    | Opcode.XRESLDTRK -> "xresldtrk"
    | Opcode.XRNG2 -> "xrng2"
    | Opcode.XRSTOR -> "xrstor"
    | Opcode.XRSTOR64 -> "xrstor64"
    | Opcode.XRSTORS -> "xrstors"
    | Opcode.XRSTORS64 -> "xrstors64"
    | Opcode.XSAVE -> "xsave"
    | Opcode.XSAVE64 -> "xsave64"
    | Opcode.XSAVEC -> "xsavec"
    | Opcode.XSAVEC64 -> "xsavec64"
    | Opcode.XSAVEOPT -> "xsaveopt"
    | Opcode.XSAVEOPT64 -> "xsaveopt64"
    | Opcode.XSAVES -> "xsaves"
    | Opcode.XSAVES64 -> "xsaves64"
    | Opcode.XSETBV -> "xsetbv"
    | Opcode.XSHA1 -> "xsha1"
    | Opcode.XSHA256 -> "xsha256"
    | Opcode.XSHA384 -> "xsha384"
    | Opcode.XSHA512 -> "xsha512"
    | Opcode.XSTORERNG -> "xstorerng"
    | Opcode.XSUSLDTRK -> "xsusldtrk"
    | Opcode.XTEST -> "xtest"
    | Opcode.InvalOP -> "(InvalOp)"
    | s -> printfn "%A" s; failwith "InvalidOpcodeException"
