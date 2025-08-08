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

namespace B2R2.FrontEnd.ARM64

open B2R2

/// <namespacedoc>
///   <summary>
///   Contains types and functions for working with the AArch64 (i.e., ARM64)
///   instructions.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents registers for ARMv8 (AArch64).<para/>
/// </summary>
type Register =
  /// X0.
  | X0 = 0x0
  /// X1.
  | X1 = 0x1
  /// X2.
  | X2 = 0x2
  /// X3.
  | X3 = 0x3
  /// X4.
  | X4 = 0x4
  /// X5.
  | X5 = 0x5
  /// X6.
  | X6 = 0x6
  /// X7.
  | X7 = 0x7
  /// X8.
  | X8 = 0x8
  /// X9.
  | X9 = 0x9
  /// X10.
  | X10 = 0xA
  /// X11.
  | X11 = 0xB
  /// X12.
  | X12 = 0xC
  /// X13.
  | X13 = 0xD
  /// X14.
  | X14 = 0xE
  /// X15.
  | X15 = 0xF
  /// X16.
  | X16 = 0x10
  /// X17.
  | X17 = 0x11
  /// X18.
  | X18 = 0x12
  /// X19.
  | X19 = 0x13
  /// X20.
  | X20 = 0x14
  /// X21.
  | X21 = 0x15
  /// X22.
  | X22 = 0x16
  /// X23.
  | X23 = 0x17
  /// X24.
  | X24 = 0x18
  /// X25.
  | X25 = 0x19
  /// X26.
  | X26 = 0x1A
  /// X27.
  | X27 = 0x1B
  /// X28.
  | X28 = 0x1C
  /// X29 (FP).
  | X29 = 0x1D
  /// X30.
  | X30 = 0x1E
  /// XZR.
  | XZR = 0x1F
  /// W0.
  | W0 = 0x20
  /// W1.
  | W1 = 0x21
  /// W2.
  | W2 = 0x22
  /// W3.
  | W3 = 0x23
  /// W4.
  | W4 = 0x24
  /// W5.
  | W5 = 0x25
  /// W6.
  | W6 = 0x26
  /// W7.
  | W7 = 0x27
  /// W8.
  | W8 = 0x28
  /// W9.
  | W9 = 0x29
  /// W10.
  | W10 = 0x2A
  /// W11.
  | W11 = 0x2B
  /// W12.
  | W12 = 0x2C
  /// W13.
  | W13 = 0x2D
  /// W14.
  | W14 = 0x2E
  /// W15.
  | W15 = 0x2F
  /// W16.
  | W16 = 0x30
  /// W17.
  | W17 = 0x31
  /// W18.
  | W18 = 0x32
  /// W19.
  | W19 = 0x33
  /// W20.
  | W20 = 0x34
  /// W21.
  | W21 = 0x35
  /// W22.
  | W22 = 0x36
  /// W23.
  | W23 = 0x37
  /// W24.
  | W24 = 0x38
  /// W25.
  | W25 = 0x39
  /// W26.
  | W26 = 0x3A
  /// W27.
  | W27 = 0x3B
  /// W28.
  | W28 = 0x3C
  /// W29.
  | W29 = 0x3D
  /// W30.
  | W30 = 0x3E
  /// WZR.
  | WZR = 0x3F
  /// Stack pointer (64bit).
  | SP = 0x40
  /// Stack pointer (32bit).
  | WSP = 0x41
  /// Program counter.
  | PC = 0x42
  /// V0.
  | V0 = 0x43
  /// V1.
  | V1 = 0x44
  /// V2.
  | V2 = 0x45
  /// V3.
  | V3 = 0x46
  /// V4.
  | V4 = 0x47
  /// V5.
  | V5 = 0x48
  /// V6.
  | V6 = 0x49
  /// V7.
  | V7 = 0x4A
  /// V8.
  | V8 = 0x4B
  /// V9.
  | V9 = 0x4C
  /// v10.
  | V10 = 0x4D
  /// V11.
  | V11 = 0x4E
  /// V12.
  | V12 = 0x4F
  /// V13.
  | V13 = 0x50
  /// V14.
  | V14 = 0x51
  /// V15.
  | V15 = 0x52
  /// V16.
  | V16 = 0x53
  /// V17.
  | V17 = 0x54
  /// V18.
  | V18 = 0x55
  /// V19.
  | V19 = 0x56
  /// V20.
  | V20 = 0x57
  /// V21.
  | V21 = 0x58
  /// V22.
  | V22 = 0x59
  /// V23.
  | V23 = 0x5A
  /// V24.
  | V24 = 0x5B
  /// V25.
  | V25 = 0x5C
  /// V26.
  | V26 = 0x5D
  /// V27.
  | V27 = 0x5E
  /// V28.
  | V28 = 0x5F
  /// V29.
  | V29 = 0x60
  /// V30.
  | V30 = 0x61
  /// V31.
  | V31 = 0x62
  /// B0.
  | B0 = 0x63
  /// B1.
  | B1 = 0x64
  /// B2.
  | B2 = 0x65
  /// B3.
  | B3 = 0x66
  /// B4.
  | B4 = 0x67
  /// B5.
  | B5 = 0x68
  /// B6.
  | B6 = 0x69
  /// B7.
  | B7 = 0x6A
  /// B8.
  | B8 = 0x6B
  /// B9.
  | B9 = 0x6C
  /// B10.
  | B10 = 0x6D
  /// B11.
  | B11 = 0x6E
  /// B12.
  | B12 = 0x6F
  /// B13.
  | B13 = 0x70
  /// B14.
  | B14 = 0x71
  /// B15.
  | B15 = 0x72
  /// B16.
  | B16 = 0x73
  /// B17.
  | B17 = 0x74
  /// B18.
  | B18 = 0x75
  /// B19.
  | B19 = 0x76
  /// B20.
  | B20 = 0x77
  /// B21.
  | B21 = 0x78
  /// B22.
  | B22 = 0x79
  /// B23.
  | B23 = 0x7A
  /// B24.
  | B24 = 0x7B
  /// B25.
  | B25 = 0x7C
  /// B26.
  | B26 = 0x7D
  /// B27.
  | B27 = 0x7E
  /// B28.
  | B28 = 0x7F
  /// B29.
  | B29 = 0x80
  /// B30.
  | B30 = 0x81
  /// B31.
  | B31 = 0x82
  /// H0.
  | H0 = 0x83
  /// H1.
  | H1 = 0x84
  /// H2.
  | H2 = 0x85
  /// H3.
  | H3 = 0x86
  /// H4.
  | H4 = 0x87
  /// H5.
  | H5 = 0x88
  /// H6.
  | H6 = 0x89
  /// H7.
  | H7 = 0x8A
  /// H8.
  | H8 = 0x8B
  /// H9.
  | H9 = 0x8C
  /// H10.
  | H10 = 0x8D
  /// H11.
  | H11 = 0x8E
  /// H12.
  | H12 = 0x8F
  /// H13.
  | H13 = 0x90
  /// H14.
  | H14 = 0x91
  /// H15.
  | H15 = 0x92
  /// H16.
  | H16 = 0x93
  /// H17.
  | H17 = 0x94
  /// H18.
  | H18 = 0x95
  /// H19.
  | H19 = 0x96
  /// H20.
  | H20 = 0x97
  /// H21.
  | H21 = 0x98
  /// H22.
  | H22 = 0x99
  /// H23.
  | H23 = 0x9A
  /// H24.
  | H24 = 0x9B
  /// H25.
  | H25 = 0x9C
  /// H26.
  | H26 = 0x9D
  /// H27.
  | H27 = 0x9E
  /// H28.
  | H28 = 0x9F
  /// H29.
  | H29 = 0xA0
  /// H30.
  | H30 = 0xA1
  /// H31.
  | H31 = 0xA2
  /// S0.
  | S0 = 0xA3
  /// S1.
  | S1 = 0xA4
  /// S2.
  | S2 = 0xA5
  /// S3.
  | S3 = 0xA6
  /// S4.
  | S4 = 0xA7
  /// S5.
  | S5 = 0xA8
  /// S6.
  | S6 = 0xA9
  /// S7.
  | S7 = 0xAA
  /// S8.
  | S8 = 0xAB
  /// S9.
  | S9 = 0xAC
  /// S10.
  | S10 = 0xAD
  /// S11.
  | S11 = 0xAE
  /// S12.
  | S12 = 0xAF
  /// S13.
  | S13 = 0xB0
  /// S14.
  | S14 = 0xB1
  /// S15.
  | S15 = 0xB2
  /// S16.
  | S16 = 0xB3
  /// S17.
  | S17 = 0xB4
  /// S18.
  | S18 = 0xB5
  /// S19.
  | S19 = 0xB6
  /// S20.
  | S20 = 0xB7
  /// S21.
  | S21 = 0xB8
  /// S22.
  | S22 = 0xB9
  /// S23.
  | S23 = 0xBA
  /// S24.
  | S24 = 0xBB
  /// S25.
  | S25 = 0xBC
  /// S26.
  | S26 = 0xBD
  /// S27.
  | S27 = 0xBE
  /// S28.
  | S28 = 0xBF
  /// S29.
  | S29 = 0xC0
  /// S30.
  | S30 = 0xC1
  /// S31.
  | S31 = 0xC2
  /// D0.
  | D0 = 0xC3
  /// D1.
  | D1 = 0xC4
  /// D2.
  | D2 = 0xC5
  /// D3.
  | D3 = 0xC6
  /// D4.
  | D4 = 0xC7
  /// D5.
  | D5 = 0xC8
  /// D6.
  | D6 = 0xC9
  /// D7.
  | D7 = 0xCA
  /// D8.
  | D8 = 0xCB
  /// D9.
  | D9 = 0xCC
  /// D10.
  | D10 = 0xCD
  /// D11.
  | D11 = 0xCE
  /// D12.
  | D12 = 0xCF
  /// D13.
  | D13 = 0xD0
  /// D14.
  | D14 = 0xD1
  /// D15.
  | D15 = 0xD2
  /// D16.
  | D16 = 0xD3
  /// D17.
  | D17 = 0xD4
  /// D18.
  | D18 = 0xD5
  /// D19.
  | D19 = 0xD6
  /// D20.
  | D20 = 0xD7
  /// D21.
  | D21 = 0xD8
  /// D22.
  | D22 = 0xD9
  /// D23.
  | D23 = 0xDA
  /// D24.
  | D24 = 0xDB
  /// D25.
  | D25 = 0xDC
  /// D26.
  | D26 = 0xDD
  /// D27.
  | D27 = 0xDE
  /// D28.
  | D28 = 0xDF
  /// D29.
  | D29 = 0xE0
  /// D30.
  | D30 = 0xE1
  /// D31.
  | D31 = 0xE2
  /// Q0.
  | Q0 = 0xE3
  /// Q1.
  | Q1 = 0xE4
  /// Q2.
  | Q2 = 0xE5
  /// Q3.
  | Q3 = 0xE6
  /// Q4.
  | Q4 = 0xE7
  /// Q5.
  | Q5 = 0xE8
  /// Q6.
  | Q6 = 0xE9
  /// Q7.
  | Q7 = 0xEA
  /// Q8.
  | Q8 = 0xEB
  /// Q9.
  | Q9 = 0xEC
  /// Q10.
  | Q10 = 0xED
  /// Q11.
  | Q11 = 0xEE
  /// Q12.
  | Q12 = 0xEF
  /// Q13.
  | Q13 = 0xF0
  /// Q14.
  | Q14 = 0xF1
  /// Q15.
  | Q15 = 0xF2
  /// Q16.
  | Q16 = 0xF3
  /// Q17.
  | Q17 = 0xF4
  /// Q18.
  | Q18 = 0xF5
  /// Q19.
  | Q19 = 0xF6
  /// Q20.
  | Q20 = 0xF7
  /// Q21.
  | Q21 = 0xF8
  /// Q22.
  | Q22 = 0xF9
  /// Q23.
  | Q23 = 0xFA
  /// Q24.
  | Q24 = 0xFB
  /// Q25.
  | Q25 = 0xFC
  /// Q26.
  | Q26 = 0xFD
  /// Q27.
  | Q27 = 0xFE
  /// Q28.
  | Q28 = 0xFF
  /// Q29.
  | Q29 = 0x100
  /// Q30.
  | Q30 = 0x101
  /// Q31.
  | Q31 = 0x102
  /// V0A is the 1st 64-bit chunk of V0A.
  | V0A = 0x103
  /// V0B is the 2nd 64-bit chunk of V0B.
  | V0B = 0x104
  ///  V1A is the 1st 64-bit chunk of V1A.
  | V1A = 0x105
  /// V1B is the 2nd 64-bit chunk of V1B.
  | V1B = 0x106
  /// V2A is the 1st 64-bit chunk of V2A.
  | V2A = 0x107
  /// V2B is the 2nd 64-bit chunk of V2B.
  | V2B = 0x108
  /// V3A is the 1st 64-bit chunk of V3A.
  | V3A = 0x109
  /// V3B is the 2nd 64-bit chunk of V3B.
  | V3B = 0x10A
  /// V4A is the 1st 64-bit chunk of V4A.
  | V4A = 0x10B
  /// V4B is the 2nd 64-bit chunk of V4B.
  | V4B = 0x10C
  /// V5A is the 1st 64-bit chunk of V5A.
  | V5A = 0x10D
  /// V5B is the 2nd 64-bit chunk of V5B.
  | V5B = 0x10E
  /// V6A is the 1st 64-bit chunk of V6A.
  | V6A = 0x10F
  /// V6B is the 2nd 64-bit chunk of V6B.
  | V6B = 0x110
  /// V7A is the 1st 64-bit chunk of V7A.
  | V7A = 0x111
  /// V7B is the 2nd 64-bit chunk of V7B.
  | V7B = 0x112
  /// V8A is the 1st 64-bit chunk of V8A.
  | V8A = 0x113
  /// V8B is the 2nd 64-bit chunk of V8B.
  | V8B = 0x114
  /// V9A is the 1st 64-bit chunk of V9A.
  | V9A = 0x115
  /// V9B is the 2nd 64-bit chunk of V9B.
  | V9B = 0x116
  /// V10A is the 1st 64-bit chunk of V10A.
  | V10A = 0x117
  /// V10B is the 2nd 64-bit chunk of V10B.
  | V10B = 0x118
  /// V11A is the 1st 64-bit chunk of V11A.
  | V11A = 0x119
  /// V11B is the 2nd 64-bit chunk of V11B.
  | V11B = 0x11A
  /// V12A is the 1st 64-bit chunk of V12A.
  | V12A = 0x11B
  /// V12B is the 2nd 64-bit chunk of V12B.
  | V12B = 0x11C
  /// V13A is the 1st 64-bit chunk of V13A.
  | V13A = 0x11D
  /// V13B is the 2nd 64-bit chunk of V13B.
  | V13B = 0x11E
  /// V14A is the 1st 64-bit chunk of V14A.
  | V14A = 0x11F
  /// V14B is the 2nd 64-bit chunk of V14B.
  | V14B = 0x120
  /// V15A is the 1st 64-bit chunk of V15A.
  | V15A = 0x121
  /// V15B is the 2nd 64-bit chunk of V15B.
  | V15B = 0x122
  /// V16A is the 1st 64-bit chunk of V16A.
  | V16A = 0x123
  /// V16B is the 2nd 64-bit chunk of V16B.
  | V16B = 0x124
  /// V17A is the 1st 64-bit chunk of V17A.
  | V17A = 0x125
  /// V17B is the 2nd 64-bit chunk of V17B.
  | V17B = 0x126
  /// V18A is the 1st 64-bit chunk of V18A.
  | V18A = 0x127
  /// V18B is the 2nd 64-bit chunk of V18B.
  | V18B = 0x128
  /// V19A is the 1st 64-bit chunk of V19A.
  | V19A = 0x129
  /// V19B is the 2nd 64-bit chunk of V19B.
  | V19B = 0x12A
  /// V20A is the 1st 64-bit chunk of V20A.
  | V20A = 0x12B
  /// V20B is the 2nd 64-bit chunk of V20B.
  | V20B = 0x12C
  /// V21A is the 1st 64-bit chunk of V21A.
  | V21A = 0x12D
  /// V21B is the 2nd 64-bit chunk of V21B.
  | V21B = 0x12E
  /// V22A is the 1st 64-bit chunk of V22A.
  | V22A = 0x12F
  /// V22B is the 2nd 64-bit chunk of V22B.
  | V22B = 0x130
  /// V23A is the 1st 64-bit chunk of V23A.
  | V23A = 0x131
  /// V23B is the 2nd 64-bit chunk of V23B.
  | V23B = 0x132
  /// V24A is the 1st 64-bit chunk of V24A.
  | V24A = 0x133
  /// V24B is the 2nd 64-bit chunk of V24B.
  | V24B = 0x134
  /// V25A is the 1st 64-bit chunk of V25A.
  | V25A = 0x135
  /// V25B is the 2nd 64-bit chunk of V25B.
  | V25B = 0x136
  /// V26A is the 1st 64-bit chunk of V26A.
  | V26A = 0x137
  /// V26B is the 2nd 64-bit chunk of V26B.
  | V26B = 0x138
  /// V27A is the 1st 64-bit chunk of V27A.
  | V27A = 0x139
  /// V27B is the 2nd 64-bit chunk of V27B.
  | V27B = 0x13A
  /// V28A is the 1st 64-bit chunk of V28A.
  | V28A = 0x13B
  /// V28B is the 2nd 64-bit chunk of V28B.
  | V28B = 0x13C
  /// V29A is the 1st 64-bit chunk of V29A.
  | V29A = 0x13D
  /// V29B is the 2nd 64-bit chunk of V29B.
  | V29B = 0x13E
  /// V30A is the 1st 64-bit chunk of V30A.
  | V30A = 0x13F
  /// V30B is the 2nd 64-bit chunk of V30B.
  | V30B = 0x140
  /// V31A is the 1st 64-bit chunk of V31A.
  | V31A = 0x141
  /// V31B is the 2nd 64-bit chunk of V31B.
  | V31B = 0x142
  /// C0.
  | C0 = 0x143
  /// C1.
  | C1 = 0x144
  /// C2.
  | C2 = 0x145
  /// C3.
  | C3 = 0x146
  /// C4.
  | C4 = 0x147
  /// C5.
  | C5 = 0x148
  /// C6
  | C6 = 0x149
  /// C7.
  | C7 = 0x14A
  /// C8.
  | C8 = 0x14B
  /// C9.
  | C9 = 0x14C
  /// C10.
  | C10 = 0x14D
  /// C11.
  | C11 = 0x14E
  /// C12.
  | C12 = 0x14F
  /// C13.
  | C13 = 0x150
  /// C14.
  | C14 = 0x151
  /// C15.
  | C15 = 0x152
  /// Negative condition flag.
  | N = 0x153
  /// Zero condition flag.
  | Z = 0x154
  /// Carry condition flag.
  | C = 0x155
  /// Overflow condition flag.
  | V = 0x156
  /// Auxiliary Control Register (EL1).
  | ACTLREL1 = 0x157
  /// Auxiliary Control Register (EL2).
  | ACTLREL2 = 0x158
  /// Auxiliary Control Register (EL3).
  | ACTLREL3 = 0x159
  /// Auxiliary Fault Status Register 0 (EL1).
  | AFSR0EL1 = 0x15A
  /// Auxiliary Fault Status Register 0 (EL2).
  | AFSR0EL2 = 0x15B
  /// Auxiliary Fault Status Register 0 (EL3).
  | AFSR0EL3 = 0x15C
  /// Auxiliary Fault Status Register 1 (EL1).
  | AFSR1EL1 = 0x15D
  /// Auxiliary Fault Status Register 1 (EL2).
  | AFSR1EL2 = 0x15E
  /// Auxiliary Fault Status Register 1 (EL3).
  | AFSR1EL3 = 0x15F
  /// Auxiliary ID Register.
  | AIDREL1 = 0x160
  /// Auxiliary Memory Attribute Indirection Register (EL1).
  | AMAIREL1 = 0x161
  /// Auxiliary Memory Attribute Indirection Register (EL2).
  | AMAIREL2 = 0x162
  /// Auxiliary Memory Attribute Indirection Register (EL3).
  | AMAIREL3 = 0x163
  /// Current Cache Size ID Register.
  | CCSIDREL1 = 0x164
  /// Cache Level ID Register.
  | CLIDREL1 = 0x165
  /// Context ID Register (EL1).
  | CONTEXTIDREL1 = 0x166
  /// Architectural Feature Access Control Register.
  | CPACREL1 = 0x167
  /// Architectural Feature Trap Register (EL2).
  | CPTREL2 = 0x168
  /// Architectural Feature Trap Register (EL3).
  | CPTREL3 = 0x169
  /// Cache Size Selection Register.
  | CSSELREL1 = 0x16A
  /// Cache Type Register.
  | CTREL0 = 0x16B
  /// Domain Access Control Register.
  | DACR32EL2 = 0x16C
  /// Data Cache Zero ID register.
  | DCZIDEL0 = 0x16D
  /// Exception Syndrome Register (EL1).
  | ESREL1 = 0x16E
  /// Exception Syndrome Register (EL2).
  | ESREL2 = 0x16F
  /// Exception Syndrome Register (EL3).
  | ESREL3 = 0x170
  /// Hypervisor IPA Fault Address Register.
  | HPFAREL2 = 0x171
  /// EL0 Read/Write Software Thread ID Register.
  | TPIDREL0 = 0x172
  /// Main ID Register.
  | MIDREL1 = 0x173
  /// Floating-point Control Register.
  | FPCR = 0x174
  /// Floating-point Status Register.
  | FPSR = 0x175
  /// Pseudo register for passing a return value from an external call. This is
  /// used to handle instruction semantics for Exclusive Monitor (EM).
  | ERET = 0x176
  /// Condition Flags.
  | NZCV = 0x177
  /// S<op0>_<op1>_<Cn>_<Cm>_<op2>.
  | S3_5_C3_C2_0 = 0x178
  | S3_7_C2_C2_7 = 0x179
  | S0_0_C2_C9_3 = 0x180
  | S2_7_C12_C7_6 = 0x181

/// Provides functions to handle ARM64 registers.
[<RequireQualifiedAccess>]
module Register =
  /// Returns the ARM64 register from a register ID.
  [<CompiledName "OfRegID">]
  let inline ofRegID (rid: RegisterID): Register =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Returns the ARM64 register from a string representation.
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant() with
    | "x0" -> Register.X0
    | "x1" -> Register.X1
    | "x2" -> Register.X2
    | "x3" -> Register.X3
    | "x4" -> Register.X4
    | "x5" -> Register.X5
    | "x6" -> Register.X6
    | "x7" -> Register.X7
    | "x8" -> Register.X8
    | "x9" -> Register.X9
    | "x10" -> Register.X10
    | "x11" -> Register.X11
    | "x12" -> Register.X12
    | "x13" -> Register.X13
    | "x14" -> Register.X14
    | "x15" -> Register.X15
    | "x16" -> Register.X16
    | "x17" -> Register.X17
    | "x18" -> Register.X18
    | "x19" -> Register.X19
    | "x20" -> Register.X20
    | "x21" -> Register.X21
    | "x22" -> Register.X22
    | "x23" -> Register.X23
    | "x24" -> Register.X24
    | "x25" -> Register.X25
    | "x26" -> Register.X26
    | "x27" -> Register.X27
    | "x28" -> Register.X28
    | "x29" -> Register.X29
    | "x30" -> Register.X30
    | "xzr" -> Register.XZR
    | "w0" -> Register.W0
    | "w1" -> Register.W1
    | "w2" -> Register.W2
    | "w3" -> Register.W3
    | "w4" -> Register.W4
    | "w5" -> Register.W5
    | "w6" -> Register.W6
    | "w7" -> Register.W7
    | "w8" -> Register.W8
    | "w9" -> Register.W9
    | "w10" -> Register.W10
    | "w11" -> Register.W11
    | "w12" -> Register.W12
    | "w13" -> Register.W13
    | "w14" -> Register.W14
    | "w15" -> Register.W15
    | "w16" -> Register.W16
    | "w17" -> Register.W17
    | "w18" -> Register.W18
    | "w19" -> Register.W19
    | "w20" -> Register.W20
    | "w21" -> Register.W21
    | "w22" -> Register.W22
    | "w23" -> Register.W23
    | "w24" -> Register.W24
    | "w25" -> Register.W25
    | "w26" -> Register.W26
    | "w27" -> Register.W27
    | "w28" -> Register.W28
    | "w29" -> Register.W29
    | "w30" -> Register.W30
    | "wzr" -> Register.WZR
    | "sp" -> Register.SP
    | "wsp" -> Register.WSP
    | "pc" -> Register.PC
    | "v0" -> Register.V0
    | "v1" -> Register.V1
    | "v2" -> Register.V2
    | "v3" -> Register.V3
    | "v4" -> Register.V4
    | "v5" -> Register.V5
    | "v6" -> Register.V6
    | "v7" -> Register.V7
    | "v8" -> Register.V8
    | "v9" -> Register.V9
    | "v10" -> Register.V10
    | "v11" -> Register.V11
    | "v12" -> Register.V12
    | "v13" -> Register.V13
    | "v14" -> Register.V14
    | "v15" -> Register.V15
    | "v16" -> Register.V16
    | "v17" -> Register.V17
    | "v18" -> Register.V18
    | "v19" -> Register.V19
    | "v20" -> Register.V20
    | "v21" -> Register.V21
    | "v22" -> Register.V22
    | "v23" -> Register.V23
    | "v24" -> Register.V24
    | "v25" -> Register.V25
    | "v26" -> Register.V26
    | "v27" -> Register.V27
    | "v28" -> Register.V28
    | "v29" -> Register.V29
    | "v30" -> Register.V30
    | "v31" -> Register.V31
    | "b0" -> Register.B0
    | "b1" -> Register.B1
    | "b2" -> Register.B2
    | "b3" -> Register.B3
    | "b4" -> Register.B4
    | "b5" -> Register.B5
    | "b6" -> Register.B6
    | "b7" -> Register.B7
    | "b8" -> Register.B8
    | "b9" -> Register.B9
    | "b10" -> Register.B10
    | "b11" -> Register.B11
    | "b12" -> Register.B12
    | "b13" -> Register.B13
    | "b14" -> Register.B14
    | "b15" -> Register.B15
    | "b16" -> Register.B16
    | "b17" -> Register.B17
    | "b18" -> Register.B18
    | "b19" -> Register.B19
    | "b20" -> Register.B20
    | "b21" -> Register.B21
    | "b22" -> Register.B22
    | "b23" -> Register.B23
    | "b24" -> Register.B24
    | "b25" -> Register.B25
    | "b26" -> Register.B26
    | "b27" -> Register.B27
    | "b28" -> Register.B28
    | "b29" -> Register.B29
    | "b30" -> Register.B30
    | "b31" -> Register.B31
    | "h0" -> Register.H0
    | "h1" -> Register.H1
    | "h2" -> Register.H2
    | "h3" -> Register.H3
    | "h4" -> Register.H4
    | "h5" -> Register.H5
    | "h6" -> Register.H6
    | "h7" -> Register.H7
    | "h8" -> Register.H8
    | "h9" -> Register.H9
    | "h10" -> Register.H10
    | "h11" -> Register.H11
    | "h12" -> Register.H12
    | "h13" -> Register.H13
    | "h14" -> Register.H14
    | "h15" -> Register.H15
    | "h16" -> Register.H16
    | "h17" -> Register.H17
    | "h18" -> Register.H18
    | "h19" -> Register.H19
    | "h20" -> Register.H20
    | "h21" -> Register.H21
    | "h22" -> Register.H22
    | "h23" -> Register.H23
    | "h24" -> Register.H24
    | "h25" -> Register.H25
    | "h26" -> Register.H26
    | "h27" -> Register.H27
    | "h28" -> Register.H28
    | "h29" -> Register.H29
    | "h30" -> Register.H30
    | "h31" -> Register.H31
    | "s0" -> Register.S0
    | "s1" -> Register.S1
    | "s2" -> Register.S2
    | "s3" -> Register.S3
    | "s4" -> Register.S4
    | "s5" -> Register.S5
    | "s6" -> Register.S6
    | "s7" -> Register.S7
    | "s8" -> Register.S8
    | "s9" -> Register.S9
    | "s10" -> Register.S10
    | "s11" -> Register.S11
    | "s12" -> Register.S12
    | "s13" -> Register.S13
    | "s14" -> Register.S14
    | "s15" -> Register.S15
    | "s16" -> Register.S16
    | "s17" -> Register.S17
    | "s18" -> Register.S18
    | "s19" -> Register.S19
    | "s20" -> Register.S20
    | "s21" -> Register.S21
    | "s22" -> Register.S22
    | "s23" -> Register.S23
    | "s24" -> Register.S24
    | "s25" -> Register.S25
    | "s26" -> Register.S26
    | "s27" -> Register.S27
    | "s28" -> Register.S28
    | "s29" -> Register.S29
    | "s30" -> Register.S30
    | "s31" -> Register.S31
    | "d0" -> Register.D0
    | "d1" -> Register.D1
    | "d2" -> Register.D2
    | "d3" -> Register.D3
    | "d4" -> Register.D4
    | "d5" -> Register.D5
    | "d6" -> Register.D6
    | "d7" -> Register.D7
    | "d8" -> Register.D8
    | "d9" -> Register.D9
    | "d10" -> Register.D10
    | "d11" -> Register.D11
    | "d12" -> Register.D12
    | "d13" -> Register.D13
    | "d14" -> Register.D14
    | "d15" -> Register.D15
    | "d16" -> Register.D16
    | "d17" -> Register.D17
    | "d18" -> Register.D18
    | "d19" -> Register.D19
    | "d20" -> Register.D20
    | "d21" -> Register.D21
    | "d22" -> Register.D22
    | "d23" -> Register.D23
    | "d24" -> Register.D24
    | "d25" -> Register.D25
    | "d26" -> Register.D26
    | "d27" -> Register.D27
    | "d28" -> Register.D28
    | "d29" -> Register.D29
    | "d30" -> Register.D30
    | "d31" -> Register.D31
    | "q0" -> Register.Q0
    | "q1" -> Register.Q1
    | "q2" -> Register.Q2
    | "q3" -> Register.Q3
    | "q4" -> Register.Q4
    | "q5" -> Register.Q5
    | "q6" -> Register.Q6
    | "q7" -> Register.Q7
    | "q8" -> Register.Q8
    | "q9" -> Register.Q9
    | "q10" -> Register.Q10
    | "q11" -> Register.Q11
    | "q12" -> Register.Q12
    | "q13" -> Register.Q13
    | "q14" -> Register.Q14
    | "q15" -> Register.Q15
    | "q16" -> Register.Q16
    | "q17" -> Register.Q17
    | "q18" -> Register.Q18
    | "q19" -> Register.Q19
    | "q20" -> Register.Q20
    | "q21" -> Register.Q21
    | "q22" -> Register.Q22
    | "q23" -> Register.Q23
    | "q24" -> Register.Q24
    | "q25" -> Register.Q25
    | "q26" -> Register.Q26
    | "q27" -> Register.Q27
    | "q28" -> Register.Q28
    | "q29" -> Register.Q29
    | "q30" -> Register.Q30
    | "q31" -> Register.Q31
    | "v0a" -> Register.V0A
    | "v0b" -> Register.V0B
    | "v1a" -> Register.V1A
    | "v1b" -> Register.V1B
    | "v2a" -> Register.V2A
    | "v2b" -> Register.V2B
    | "v3a" -> Register.V3A
    | "v3b" -> Register.V3B
    | "v4a" -> Register.V4A
    | "v4b" -> Register.V4B
    | "v5a" -> Register.V5A
    | "v5b" -> Register.V5B
    | "v6a" -> Register.V6A
    | "v6b" -> Register.V6B
    | "v7a" -> Register.V7A
    | "v7b" -> Register.V7B
    | "v8a" -> Register.V8A
    | "v8b" -> Register.V8B
    | "v9a" -> Register.V9A
    | "v9b" -> Register.V9B
    | "v10a" -> Register.V10A
    | "v10b" -> Register.V10B
    | "v11a" -> Register.V11A
    | "v11b" -> Register.V11B
    | "v12a" -> Register.V12A
    | "v12b" -> Register.V12B
    | "v13a" -> Register.V13A
    | "v13b" -> Register.V13B
    | "v14a" -> Register.V14A
    | "v14b" -> Register.V14B
    | "v15a" -> Register.V15A
    | "v15b" -> Register.V15B
    | "v16a" -> Register.V16A
    | "v16b" -> Register.V16B
    | "v17a" -> Register.V17A
    | "v17b" -> Register.V17B
    | "v18a" -> Register.V18A
    | "v18b" -> Register.V18B
    | "v19a" -> Register.V19A
    | "v19b" -> Register.V19B
    | "v20a" -> Register.V20A
    | "v20b" -> Register.V20B
    | "v21a" -> Register.V21A
    | "v21b" -> Register.V21B
    | "v22a" -> Register.V22A
    | "v22b" -> Register.V22B
    | "v23a" -> Register.V23A
    | "v23b" -> Register.V23B
    | "v24a" -> Register.V24A
    | "v24b" -> Register.V24B
    | "v25a" -> Register.V25A
    | "v25b" -> Register.V25B
    | "v26a" -> Register.V26A
    | "v26b" -> Register.V26B
    | "v27a" -> Register.V27A
    | "v27b" -> Register.V27B
    | "v28a" -> Register.V28A
    | "v28b" -> Register.V28B
    | "v29a" -> Register.V29A
    | "v29b" -> Register.V29B
    | "v30a" -> Register.V30A
    | "v30b" -> Register.V30B
    | "v31a" -> Register.V31A
    | "v31b" -> Register.V31B
    | "c0" -> Register.C0
    | "c1" -> Register.C1
    | "c2" -> Register.C2
    | "c3" -> Register.C3
    | "c4" -> Register.C4
    | "c5" -> Register.C5
    | "c6" -> Register.C6
    | "c7" -> Register.C7
    | "c8" -> Register.C8
    | "c9" -> Register.C9
    | "c10" -> Register.C10
    | "c11" -> Register.C11
    | "c12" -> Register.C12
    | "c13" -> Register.C13
    | "c14" -> Register.C14
    | "c15" -> Register.C15
    | "n" -> Register.N
    | "z" -> Register.Z
    | "c" -> Register.C
    | "v" -> Register.V
    | "actlrel1" -> Register.ACTLREL1
    | "actlrel2" -> Register.ACTLREL2
    | "actlrel3" -> Register.ACTLREL3
    | "afsr0el1" -> Register.AFSR0EL1
    | "afsr0el2" -> Register.AFSR0EL2
    | "afsr0el3" -> Register.AFSR0EL3
    | "afsr1el1" -> Register.AFSR1EL1
    | "afsr1el2" -> Register.AFSR1EL2
    | "afsr1el3" -> Register.AFSR1EL3
    | "aidrel1" -> Register.AIDREL1
    | "amairel1" -> Register.AMAIREL1
    | "amairel2" -> Register.AMAIREL2
    | "amairel3" -> Register.AMAIREL3
    | "ccsidrel1" -> Register.CCSIDREL1
    | "clidrel1" -> Register.CLIDREL1
    | "contextidrel1" -> Register.CONTEXTIDREL1
    | "cpacrel1" -> Register.CPACREL1
    | "cptrel2" -> Register.CPTREL2
    | "cptrel3" -> Register.CPTREL3
    | "csselrel1" -> Register.CSSELREL1
    | "ctrel0" -> Register.CTREL0
    | "dacr32el2" -> Register.DACR32EL2
    | "dczidel0" -> Register.DCZIDEL0
    | "esrel1" -> Register.ESREL1
    | "esrel2" -> Register.ESREL2
    | "esrel3" -> Register.ESREL3
    | "hpfarel2" -> Register.HPFAREL2
    | "tpidrel0" -> Register.TPIDREL0
    | "midrel1" -> Register.MIDREL1
    | "fpcr" -> Register.FPCR
    | "fpsr" -> Register.FPSR
    | "eret" -> Register.ERET
    | "nzcv" -> Register.NZCV
    | "s3_5_c3_c2_0" -> Register.S3_5_C3_C2_0
    | "s3_7_c2_c2_7" -> Register.S3_7_C2_C2_7
    | "s0_0_c2_c9_3" -> Register.S0_0_C2_C9_3
    | "s2_7_c12_c7_6" -> Register.S2_7_C12_C7_6
    | _ -> Terminator.impossible ()

  /// Returns the register ID of an ARM64 register.
  [<CompiledName "ToRegID">]
  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue(reg) |> RegisterID.create

  /// Returns the string representation of an ARM64 register.
  [<CompiledName "ToString">]
  let toString reg =
    match reg with
    | Register.X0 -> "x0"
    | Register.X1 -> "x1"
    | Register.X2 -> "x2"
    | Register.X3 -> "x3"
    | Register.X4 -> "x4"
    | Register.X5 -> "x5"
    | Register.X6 -> "x6"
    | Register.X7 -> "x7"
    | Register.X8 -> "x8"
    | Register.X9 -> "x9"
    | Register.X10 -> "x10"
    | Register.X11 -> "x11"
    | Register.X12 -> "x12"
    | Register.X13 -> "x13"
    | Register.X14 -> "x14"
    | Register.X15 -> "x15"
    | Register.X16 -> "x16"
    | Register.X17 -> "x17"
    | Register.X18 -> "x18"
    | Register.X19 -> "x19"
    | Register.X20 -> "x20"
    | Register.X21 -> "x21"
    | Register.X22 -> "x22"
    | Register.X23 -> "x23"
    | Register.X24 -> "x24"
    | Register.X25 -> "x25"
    | Register.X26 -> "x26"
    | Register.X27 -> "x27"
    | Register.X28 -> "x28"
    | Register.X29 -> "x29"
    | Register.X30 -> "x30"
    | Register.XZR -> "xzr"
    | Register.W0 -> "w0"
    | Register.W1 -> "w1"
    | Register.W2 -> "w2"
    | Register.W3 -> "w3"
    | Register.W4 -> "w4"
    | Register.W5 -> "w5"
    | Register.W6 -> "w6"
    | Register.W7 -> "w7"
    | Register.W8 -> "w8"
    | Register.W9 -> "w9"
    | Register.W10 -> "w10"
    | Register.W11 -> "w11"
    | Register.W12 -> "w12"
    | Register.W13 -> "w13"
    | Register.W14 -> "w14"
    | Register.W15 -> "w15"
    | Register.W16 -> "w16"
    | Register.W17 -> "w17"
    | Register.W18 -> "w18"
    | Register.W19 -> "w19"
    | Register.W20 -> "w20"
    | Register.W21 -> "w21"
    | Register.W22 -> "w22"
    | Register.W23 -> "w23"
    | Register.W24 -> "w24"
    | Register.W25 -> "w25"
    | Register.W26 -> "w26"
    | Register.W27 -> "w27"
    | Register.W28 -> "w28"
    | Register.W29 -> "w29"
    | Register.W30 -> "w30"
    | Register.WZR -> "wzr"
    | Register.SP -> "sp"
    | Register.WSP -> "wsp"
    | Register.PC -> "pc"
    | Register.V0 -> "v0"
    | Register.V1 -> "v1"
    | Register.V2 -> "v2"
    | Register.V3 -> "v3"
    | Register.V4 -> "v4"
    | Register.V5 -> "v5"
    | Register.V6 -> "v6"
    | Register.V7 -> "v7"
    | Register.V8 -> "v8"
    | Register.V9 -> "v9"
    | Register.V10 -> "v10"
    | Register.V11 -> "v11"
    | Register.V12 -> "v12"
    | Register.V13 -> "v13"
    | Register.V14 -> "v14"
    | Register.V15 -> "v15"
    | Register.V16 -> "v16"
    | Register.V17 -> "v17"
    | Register.V18 -> "v18"
    | Register.V19 -> "v19"
    | Register.V20 -> "v20"
    | Register.V21 -> "v21"
    | Register.V22 -> "v22"
    | Register.V23 -> "v23"
    | Register.V24 -> "v24"
    | Register.V25 -> "v25"
    | Register.V26 -> "v26"
    | Register.V27 -> "v27"
    | Register.V28 -> "v28"
    | Register.V29 -> "v29"
    | Register.V30 -> "v30"
    | Register.V31 -> "v31"
    | Register.B0 -> "b0"
    | Register.B1 -> "b1"
    | Register.B2 -> "b2"
    | Register.B3 -> "b3"
    | Register.B4 -> "b4"
    | Register.B5 -> "b5"
    | Register.B6 -> "b6"
    | Register.B7 -> "b7"
    | Register.B8 -> "b8"
    | Register.B9 -> "b9"
    | Register.B10 -> "b10"
    | Register.B11 -> "b11"
    | Register.B12 -> "b12"
    | Register.B13 -> "b13"
    | Register.B14 -> "b14"
    | Register.B15 -> "b15"
    | Register.B16 -> "b16"
    | Register.B17 -> "b17"
    | Register.B18 -> "b18"
    | Register.B19 -> "b19"
    | Register.B20 -> "b20"
    | Register.B21 -> "b21"
    | Register.B22 -> "b22"
    | Register.B23 -> "b23"
    | Register.B24 -> "b24"
    | Register.B25 -> "b25"
    | Register.B26 -> "b26"
    | Register.B27 -> "b27"
    | Register.B28 -> "b28"
    | Register.B29 -> "b29"
    | Register.B30 -> "b30"
    | Register.B31 -> "b31"
    | Register.H0 -> "h0"
    | Register.H1 -> "h1"
    | Register.H2 -> "h2"
    | Register.H3 -> "h3"
    | Register.H4 -> "h4"
    | Register.H5 -> "h5"
    | Register.H6 -> "h6"
    | Register.H7 -> "h7"
    | Register.H8 -> "h8"
    | Register.H9 -> "h9"
    | Register.H10 -> "h10"
    | Register.H11 -> "h11"
    | Register.H12 -> "h12"
    | Register.H13 -> "h13"
    | Register.H14 -> "h14"
    | Register.H15 -> "h15"
    | Register.H16 -> "h16"
    | Register.H17 -> "h17"
    | Register.H18 -> "h18"
    | Register.H19 -> "h19"
    | Register.H20 -> "h20"
    | Register.H21 -> "h21"
    | Register.H22 -> "h22"
    | Register.H23 -> "h23"
    | Register.H24 -> "h24"
    | Register.H25 -> "h25"
    | Register.H26 -> "h26"
    | Register.H27 -> "h27"
    | Register.H28 -> "h28"
    | Register.H29 -> "h29"
    | Register.H30 -> "h30"
    | Register.H31 -> "h31"
    | Register.S0 -> "s0"
    | Register.S1 -> "s1"
    | Register.S2 -> "s2"
    | Register.S3 -> "s3"
    | Register.S4 -> "s4"
    | Register.S5 -> "s5"
    | Register.S6 -> "s6"
    | Register.S7 -> "s7"
    | Register.S8 -> "s8"
    | Register.S9 -> "s9"
    | Register.S10 -> "s10"
    | Register.S11 -> "s11"
    | Register.S12 -> "s12"
    | Register.S13 -> "s13"
    | Register.S14 -> "s14"
    | Register.S15 -> "s15"
    | Register.S16 -> "s16"
    | Register.S17 -> "s17"
    | Register.S18 -> "s18"
    | Register.S19 -> "s19"
    | Register.S20 -> "s20"
    | Register.S21 -> "s21"
    | Register.S22 -> "s22"
    | Register.S23 -> "s23"
    | Register.S24 -> "s24"
    | Register.S25 -> "s25"
    | Register.S26 -> "s26"
    | Register.S27 -> "s27"
    | Register.S28 -> "s28"
    | Register.S29 -> "s29"
    | Register.S30 -> "s30"
    | Register.S31 -> "s31"
    | Register.D0 -> "d0"
    | Register.D1 -> "d1"
    | Register.D2 -> "d2"
    | Register.D3 -> "d3"
    | Register.D4 -> "d4"
    | Register.D5 -> "d5"
    | Register.D6 -> "d6"
    | Register.D7 -> "d7"
    | Register.D8 -> "d8"
    | Register.D9 -> "d9"
    | Register.D10 -> "d10"
    | Register.D11 -> "d11"
    | Register.D12 -> "d12"
    | Register.D13 -> "d13"
    | Register.D14 -> "d14"
    | Register.D15 -> "d15"
    | Register.D16 -> "d16"
    | Register.D17 -> "d17"
    | Register.D18 -> "d18"
    | Register.D19 -> "d19"
    | Register.D20 -> "d20"
    | Register.D21 -> "d21"
    | Register.D22 -> "d22"
    | Register.D23 -> "d23"
    | Register.D24 -> "d24"
    | Register.D25 -> "d25"
    | Register.D26 -> "d26"
    | Register.D27 -> "d27"
    | Register.D28 -> "d28"
    | Register.D29 -> "d29"
    | Register.D30 -> "d30"
    | Register.D31 -> "d31"
    | Register.Q0 -> "q0"
    | Register.Q1 -> "q1"
    | Register.Q2 -> "q2"
    | Register.Q3 -> "q3"
    | Register.Q4 -> "q4"
    | Register.Q5 -> "q5"
    | Register.Q6 -> "q6"
    | Register.Q7 -> "q7"
    | Register.Q8 -> "q8"
    | Register.Q9 -> "q9"
    | Register.Q10 -> "q10"
    | Register.Q11 -> "q11"
    | Register.Q12 -> "q12"
    | Register.Q13 -> "q13"
    | Register.Q14 -> "q14"
    | Register.Q15 -> "q15"
    | Register.Q16 -> "q16"
    | Register.Q17 -> "q17"
    | Register.Q18 -> "q18"
    | Register.Q19 -> "q19"
    | Register.Q20 -> "q20"
    | Register.Q21 -> "q21"
    | Register.Q22 -> "q22"
    | Register.Q23 -> "q23"
    | Register.Q24 -> "q24"
    | Register.Q25 -> "q25"
    | Register.Q26 -> "q26"
    | Register.Q27 -> "q27"
    | Register.Q28 -> "q28"
    | Register.Q29 -> "q29"
    | Register.Q30 -> "q30"
    | Register.Q31 -> "q31"
    | Register.V0A -> "v0a"
    | Register.V0B -> "v0b"
    | Register.V1A -> "v1a"
    | Register.V1B -> "v1b"
    | Register.V2A -> "v2a"
    | Register.V2B -> "v2b"
    | Register.V3A -> "v3a"
    | Register.V3B -> "v3b"
    | Register.V4A -> "v4a"
    | Register.V4B -> "v4b"
    | Register.V5A -> "v5a"
    | Register.V5B -> "v5b"
    | Register.V6A -> "v6a"
    | Register.V6B -> "v6b"
    | Register.V7A -> "v7a"
    | Register.V7B -> "v7b"
    | Register.V8A -> "v8a"
    | Register.V8B -> "v8b"
    | Register.V9A -> "v9a"
    | Register.V9B -> "v9b"
    | Register.V10A -> "v10a"
    | Register.V10B -> "v10b"
    | Register.V11A -> "v11a"
    | Register.V11B -> "v11b"
    | Register.V12A -> "v12a"
    | Register.V12B -> "v12b"
    | Register.V13A -> "v13a"
    | Register.V13B -> "v13b"
    | Register.V14A -> "v14a"
    | Register.V14B -> "v14b"
    | Register.V15A -> "v15a"
    | Register.V15B -> "v15b"
    | Register.V16A -> "v16a"
    | Register.V16B -> "v16b"
    | Register.V17A -> "v17a"
    | Register.V17B -> "v17b"
    | Register.V18A -> "v18a"
    | Register.V18B -> "v18b"
    | Register.V19A -> "v19a"
    | Register.V19B -> "v19b"
    | Register.V20A -> "v20a"
    | Register.V20B -> "v20b"
    | Register.V21A -> "v21a"
    | Register.V21B -> "v21b"
    | Register.V22A -> "v22a"
    | Register.V22B -> "v22b"
    | Register.V23A -> "v23a"
    | Register.V23B -> "v23b"
    | Register.V24A -> "v24a"
    | Register.V24B -> "v24b"
    | Register.V25A -> "v25a"
    | Register.V25B -> "v25b"
    | Register.V26A -> "v26a"
    | Register.V26B -> "v26b"
    | Register.V27A -> "v27a"
    | Register.V27B -> "v27b"
    | Register.V28A -> "v28a"
    | Register.V28B -> "v28b"
    | Register.V29A -> "v29a"
    | Register.V29B -> "v29b"
    | Register.V30A -> "v30a"
    | Register.V30B -> "v30b"
    | Register.V31A -> "v31a"
    | Register.V31B -> "v31b"
    | Register.C0 -> "c0"
    | Register.C1 -> "c1"
    | Register.C2 -> "c2"
    | Register.C3 -> "c3"
    | Register.C4 -> "c4"
    | Register.C5 -> "c5"
    | Register.C6 -> "c6"
    | Register.C7 -> "c7"
    | Register.C8 -> "c8"
    | Register.C9 -> "c9"
    | Register.C10 -> "c10"
    | Register.C11 -> "c11"
    | Register.C12 -> "c12"
    | Register.C13 -> "c13"
    | Register.C14 -> "c14"
    | Register.C15 -> "c15"
    | Register.N -> "n"
    | Register.Z -> "z"
    | Register.C -> "c"
    | Register.V -> "v"
    | Register.ACTLREL1 -> "actlr_el1"
    | Register.ACTLREL2 -> "actlr_el2"
    | Register.ACTLREL3 -> "actlr_el3"
    | Register.AFSR0EL1 -> "afsr0_el1"
    | Register.AFSR0EL2 -> "afsr0_el2"
    | Register.AFSR0EL3 -> "afsr0_el3"
    | Register.AFSR1EL1 -> "afsr1_el1"
    | Register.AFSR1EL2 -> "afsr1_el2"
    | Register.AFSR1EL3 -> "afsr1_el3"
    | Register.AIDREL1 -> "aidr_el1"
    | Register.AMAIREL1 -> "amair_el1"
    | Register.AMAIREL2 -> "amair_el2"
    | Register.AMAIREL3 -> "amair_el3"
    | Register.CCSIDREL1 -> "ccsidr_el1"
    | Register.CLIDREL1 -> "clidr_el1"
    | Register.CONTEXTIDREL1 -> "contextidr_el1"
    | Register.CPACREL1 -> "cpacr_el1"
    | Register.CPTREL2 -> "cptr_el2"
    | Register.CPTREL3 -> "cptr_el3"
    | Register.CSSELREL1 -> "csselr_el1"
    | Register.CTREL0 -> "ctr_el0"
    | Register.DACR32EL2 -> "dacr32_el2"
    | Register.DCZIDEL0 -> "dczid_el0"
    | Register.ESREL1 -> "esr_el1"
    | Register.ESREL2 -> "esr_el2"
    | Register.ESREL3 -> "esr_el3"
    | Register.HPFAREL2 -> "hpfar_el2"
    | Register.TPIDREL0 -> "tpidr_el0"
    | Register.MIDREL1 -> "midr_el1"
    | Register.FPCR -> "fpcr"
    | Register.FPSR -> "fpsr"
    | Register.ERET -> "eret"
    | Register.NZCV -> "nzcv"
    | Register.S3_5_C3_C2_0 -> "s3_5_c3_c2_0"
    | Register.S3_7_C2_C2_7 -> "s3_7_c2_c2_7"
    | Register.S0_0_C2_C9_3 -> "s0_0_c2_c9_3"
    | Register.S2_7_C12_C7_6 -> "s2_7_c12_c7_6"
    | _ -> Terminator.impossible ()
