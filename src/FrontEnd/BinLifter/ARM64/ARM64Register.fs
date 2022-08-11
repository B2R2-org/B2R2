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

namespace B2R2.FrontEnd.BinLifter.ARM64

open B2R2

/// ARMv8 (AArch64) registers.
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
  /// Floating-point Control Register.
  | FPCR = 0x173
  /// Floating-point Status Register.
  | FPSR = 0x174

/// Shortcut for Register type.
type internal R = Register

/// This module exposes several useful functions to handle ARMv8 registers.
[<RequireQualifiedAccess>]
module Register =
  let inline ofRegID (n: RegisterID): Register =
    int n |> LanguagePrimitives.EnumOfValue

  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  let ofString (str: string) =
    match str.ToLowerInvariant () with
    | "x0" -> R.X0
    | "x1" -> R.X1
    | "x2" -> R.X2
    | "x3" -> R.X3
    | "x4" -> R.X4
    | "x5" -> R.X5
    | "x6" -> R.X6
    | "x7" -> R.X7
    | "x8" -> R.X8
    | "x9" -> R.X9
    | "x10" -> R.X10
    | "x11" -> R.X11
    | "x12" -> R.X12
    | "x13" -> R.X13
    | "x14" -> R.X14
    | "x15" -> R.X15
    | "x16" -> R.X16
    | "x17" -> R.X17
    | "x18" -> R.X18
    | "x19" -> R.X19
    | "x20" -> R.X20
    | "x21" -> R.X21
    | "x22" -> R.X22
    | "x23" -> R.X23
    | "x24" -> R.X24
    | "x25" -> R.X25
    | "x26" -> R.X26
    | "x27" -> R.X27
    | "x28" -> R.X28
    | "x29" -> R.X29
    | "x30" -> R.X30
    | "xzr" -> R.XZR
    | "w0" -> R.W0
    | "w1" -> R.W1
    | "w2" -> R.W2
    | "w3" -> R.W3
    | "w4" -> R.W4
    | "w5" -> R.W5
    | "w6" -> R.W6
    | "w7" -> R.W7
    | "w8" -> R.W8
    | "w9" -> R.W9
    | "w10" -> R.W10
    | "w11" -> R.W11
    | "w12" -> R.W12
    | "w13" -> R.W13
    | "w14" -> R.W14
    | "w15" -> R.W15
    | "w16" -> R.W16
    | "w17" -> R.W17
    | "w18" -> R.W18
    | "w19" -> R.W19
    | "w20" -> R.W20
    | "w21" -> R.W21
    | "w22" -> R.W22
    | "w23" -> R.W23
    | "w24" -> R.W24
    | "w25" -> R.W25
    | "w26" -> R.W26
    | "w27" -> R.W27
    | "w28" -> R.W28
    | "w29" -> R.W29
    | "w30" -> R.W30
    | "wzr" -> R.WZR
    | "sp" -> R.SP
    | "wsp" -> R.WSP
    | "pc" -> R.PC
    | "v0" -> R.V0
    | "v1" -> R.V1
    | "v2" -> R.V2
    | "v3" -> R.V3
    | "v4" -> R.V4
    | "v5" -> R.V5
    | "v6" -> R.V6
    | "v7" -> R.V7
    | "v8" -> R.V8
    | "v9" -> R.V9
    | "v10" -> R.V10
    | "v11" -> R.V11
    | "v12" -> R.V12
    | "v13" -> R.V13
    | "v14" -> R.V14
    | "v15" -> R.V15
    | "v16" -> R.V16
    | "v17" -> R.V17
    | "v18" -> R.V18
    | "v19" -> R.V19
    | "v20" -> R.V20
    | "v21" -> R.V21
    | "v22" -> R.V22
    | "v23" -> R.V23
    | "v24" -> R.V24
    | "v25" -> R.V25
    | "v26" -> R.V26
    | "v27" -> R.V27
    | "v28" -> R.V28
    | "v29" -> R.V29
    | "v30" -> R.V30
    | "v31" -> R.V31
    | "b0" -> R.B0
    | "b1" -> R.B1
    | "b2" -> R.B2
    | "b3" -> R.B3
    | "b4" -> R.B4
    | "b5" -> R.B5
    | "b6" -> R.B6
    | "b7" -> R.B7
    | "b8" -> R.B8
    | "b9" -> R.B9
    | "b10" -> R.B10
    | "b11" -> R.B11
    | "b12" -> R.B12
    | "b13" -> R.B13
    | "b14" -> R.B14
    | "b15" -> R.B15
    | "b16" -> R.B16
    | "b17" -> R.B17
    | "b18" -> R.B18
    | "b19" -> R.B19
    | "b20" -> R.B20
    | "b21" -> R.B21
    | "b22" -> R.B22
    | "b23" -> R.B23
    | "b24" -> R.B24
    | "b25" -> R.B25
    | "b26" -> R.B26
    | "b27" -> R.B27
    | "b28" -> R.B28
    | "b29" -> R.B29
    | "b30" -> R.B30
    | "b31" -> R.B31
    | "h0" -> R.H0
    | "h1" -> R.H1
    | "h2" -> R.H2
    | "h3" -> R.H3
    | "h4" -> R.H4
    | "h5" -> R.H5
    | "h6" -> R.H6
    | "h7" -> R.H7
    | "h8" -> R.H8
    | "h9" -> R.H9
    | "h10" -> R.H10
    | "h11" -> R.H11
    | "h12" -> R.H12
    | "h13" -> R.H13
    | "h14" -> R.H14
    | "h15" -> R.H15
    | "h16" -> R.H16
    | "h17" -> R.H17
    | "h18" -> R.H18
    | "h19" -> R.H19
    | "h20" -> R.H20
    | "h21" -> R.H21
    | "h22" -> R.H22
    | "h23" -> R.H23
    | "h24" -> R.H24
    | "h25" -> R.H25
    | "h26" -> R.H26
    | "h27" -> R.H27
    | "h28" -> R.H28
    | "h29" -> R.H29
    | "h30" -> R.H30
    | "h31" -> R.H31
    | "s0" -> R.S0
    | "s1" -> R.S1
    | "s2" -> R.S2
    | "s3" -> R.S3
    | "s4" -> R.S4
    | "s5" -> R.S5
    | "s6" -> R.S6
    | "s7" -> R.S7
    | "s8" -> R.S8
    | "s9" -> R.S9
    | "s10" -> R.S10
    | "s11" -> R.S11
    | "s12" -> R.S12
    | "s13" -> R.S13
    | "s14" -> R.S14
    | "s15" -> R.S15
    | "s16" -> R.S16
    | "s17" -> R.S17
    | "s18" -> R.S18
    | "s19" -> R.S19
    | "s20" -> R.S20
    | "s21" -> R.S21
    | "s22" -> R.S22
    | "s23" -> R.S23
    | "s24" -> R.S24
    | "s25" -> R.S25
    | "s26" -> R.S26
    | "s27" -> R.S27
    | "s28" -> R.S28
    | "s29" -> R.S29
    | "s30" -> R.S30
    | "s31" -> R.S31
    | "d0" -> R.D0
    | "d1" -> R.D1
    | "d2" -> R.D2
    | "d3" -> R.D3
    | "d4" -> R.D4
    | "d5" -> R.D5
    | "d6" -> R.D6
    | "d7" -> R.D7
    | "d8" -> R.D8
    | "d9" -> R.D9
    | "d10" -> R.D10
    | "d11" -> R.D11
    | "d12" -> R.D12
    | "d13" -> R.D13
    | "d14" -> R.D14
    | "d15" -> R.D15
    | "d16" -> R.D16
    | "d17" -> R.D17
    | "d18" -> R.D18
    | "d19" -> R.D19
    | "d20" -> R.D20
    | "d21" -> R.D21
    | "d22" -> R.D22
    | "d23" -> R.D23
    | "d24" -> R.D24
    | "d25" -> R.D25
    | "d26" -> R.D26
    | "d27" -> R.D27
    | "d28" -> R.D28
    | "d29" -> R.D29
    | "d30" -> R.D30
    | "d31" -> R.D31
    | "q0" -> R.Q0
    | "q1" -> R.Q1
    | "q2" -> R.Q2
    | "q3" -> R.Q3
    | "q4" -> R.Q4
    | "q5" -> R.Q5
    | "q6" -> R.Q6
    | "q7" -> R.Q7
    | "q8" -> R.Q8
    | "q9" -> R.Q9
    | "q10" -> R.Q10
    | "q11" -> R.Q11
    | "q12" -> R.Q12
    | "q13" -> R.Q13
    | "q14" -> R.Q14
    | "q15" -> R.Q15
    | "q16" -> R.Q16
    | "q17" -> R.Q17
    | "q18" -> R.Q18
    | "q19" -> R.Q19
    | "q20" -> R.Q20
    | "q21" -> R.Q21
    | "q22" -> R.Q22
    | "q23" -> R.Q23
    | "q24" -> R.Q24
    | "q25" -> R.Q25
    | "q26" -> R.Q26
    | "q27" -> R.Q27
    | "q28" -> R.Q28
    | "q29" -> R.Q29
    | "q30" -> R.Q30
    | "q31" -> R.Q31
    | "v0a" -> R.V0A
    | "v0b" -> R.V0B
    | "v1a" -> R.V1A
    | "v1b" -> R.V1B
    | "v2a" -> R.V2A
    | "v2b" -> R.V2B
    | "v3a" -> R.V3A
    | "v3b" -> R.V3B
    | "v4a" -> R.V4A
    | "v4b" -> R.V4B
    | "v5a" -> R.V5A
    | "v5b" -> R.V5B
    | "v6a" -> R.V6A
    | "v6b" -> R.V6B
    | "v7a" -> R.V7A
    | "v7b" -> R.V7B
    | "v8a" -> R.V8A
    | "v8b" -> R.V8B
    | "v9a" -> R.V9A
    | "v9b" -> R.V9B
    | "v10a" -> R.V10A
    | "v10b" -> R.V10B
    | "v11a" -> R.V11A
    | "v11b" -> R.V11B
    | "v12a" -> R.V12A
    | "v12b" -> R.V12B
    | "v13a" -> R.V13A
    | "v13b" -> R.V13B
    | "v14a" -> R.V14A
    | "v14b" -> R.V14B
    | "v15a" -> R.V15A
    | "v15b" -> R.V15B
    | "v16a" -> R.V16A
    | "v16b" -> R.V16B
    | "v17a" -> R.V17A
    | "v17b" -> R.V17B
    | "v18a" -> R.V18A
    | "v18b" -> R.V18B
    | "v19a" -> R.V19A
    | "v19b" -> R.V19B
    | "v20a" -> R.V20A
    | "v20b" -> R.V20B
    | "v21a" -> R.V21A
    | "v21b" -> R.V21B
    | "v22a" -> R.V22A
    | "v22b" -> R.V22B
    | "v23a" -> R.V23A
    | "v23b" -> R.V23B
    | "v24a" -> R.V24A
    | "v24b" -> R.V24B
    | "v25a" -> R.V25A
    | "v25b" -> R.V25B
    | "v26a" -> R.V26A
    | "v26b" -> R.V26B
    | "v27a" -> R.V27A
    | "v27b" -> R.V27B
    | "v28a" -> R.V28A
    | "v28b" -> R.V28B
    | "v29a" -> R.V29A
    | "v29b" -> R.V29B
    | "v30a" -> R.V30A
    | "v30b" -> R.V30B
    | "v31a" -> R.V31A
    | "v31b" -> R.V31B
    | "c0" -> R.C0
    | "c1" -> R.C1
    | "c2" -> R.C2
    | "c3" -> R.C3
    | "c4" -> R.C4
    | "c5" -> R.C5
    | "c6" -> R.C6
    | "c7" -> R.C7
    | "c8" -> R.C8
    | "c9" -> R.C9
    | "c10" -> R.C10
    | "c11" -> R.C11
    | "c12" -> R.C12
    | "c13" -> R.C13
    | "c14" -> R.C14
    | "c15" -> R.C15
    | "n" -> R.N
    | "z" -> R.Z
    | "c" -> R.C
    | "v" -> R.V
    | "actlrel1" -> R.ACTLREL1
    | "actlrel2" -> R.ACTLREL2
    | "actlrel3" -> R.ACTLREL3
    | "afsr0el1" -> R.AFSR0EL1
    | "afsr0el2" -> R.AFSR0EL2
    | "afsr0el3" -> R.AFSR0EL3
    | "afsr1el1" -> R.AFSR1EL1
    | "afsr1el2" -> R.AFSR1EL2
    | "afsr1el3" -> R.AFSR1EL3
    | "aidrel1" -> R.AIDREL1
    | "amairel1" -> R.AMAIREL1
    | "amairel2" -> R.AMAIREL2
    | "amairel3" -> R.AMAIREL3
    | "ccsidrel1" -> R.CCSIDREL1
    | "clidrel1" -> R.CLIDREL1
    | "contextidrel1" -> R.CONTEXTIDREL1
    | "cpacrel1" -> R.CPACREL1
    | "cptrel2" -> R.CPTREL2
    | "cptrel3" -> R.CPTREL3
    | "csselrel1" -> R.CSSELREL1
    | "ctrel0" -> R.CTREL0
    | "dacr32el2" -> R.DACR32EL2
    | "dczidel0" -> R.DCZIDEL0
    | "esrel1" -> R.ESREL1
    | "esrel2" -> R.ESREL2
    | "esrel3" -> R.ESREL3
    | "hpfarel2" -> R.HPFAREL2
    | "tpidrel0" -> R.TPIDREL0
    | "fpcr" -> R.FPCR
    | "fpsr" -> R.FPSR
    | _ -> Utils.impossible ()

  let toString = function
    | R.X0 -> "x0"
    | R.X1 -> "x1"
    | R.X2 -> "x2"
    | R.X3 -> "x3"
    | R.X4 -> "x4"
    | R.X5 -> "x5"
    | R.X6 -> "x6"
    | R.X7 -> "x7"
    | R.X8 -> "x8"
    | R.X9 -> "x9"
    | R.X10 -> "x10"
    | R.X11 -> "x11"
    | R.X12 -> "x12"
    | R.X13 -> "x13"
    | R.X14 -> "x14"
    | R.X15 -> "x15"
    | R.X16 -> "x16"
    | R.X17 -> "x17"
    | R.X18 -> "x18"
    | R.X19 -> "x19"
    | R.X20 -> "x20"
    | R.X21 -> "x21"
    | R.X22 -> "x22"
    | R.X23 -> "x23"
    | R.X24 -> "x24"
    | R.X25 -> "x25"
    | R.X26 -> "x26"
    | R.X27 -> "x27"
    | R.X28 -> "x28"
    | R.X29 -> "x29"
    | R.X30 -> "x30"
    | R.XZR -> "xzr"
    | R.W0 -> "w0"
    | R.W1 -> "w1"
    | R.W2 -> "w2"
    | R.W3 -> "w3"
    | R.W4 -> "w4"
    | R.W5 -> "w5"
    | R.W6 -> "w6"
    | R.W7 -> "w7"
    | R.W8 -> "w8"
    | R.W9 -> "w9"
    | R.W10 -> "w10"
    | R.W11 -> "w11"
    | R.W12 -> "w12"
    | R.W13 -> "w13"
    | R.W14 -> "w14"
    | R.W15 -> "w15"
    | R.W16 -> "w16"
    | R.W17 -> "w17"
    | R.W18 -> "w18"
    | R.W19 -> "w19"
    | R.W20 -> "w20"
    | R.W21 -> "w21"
    | R.W22 -> "w22"
    | R.W23 -> "w23"
    | R.W24 -> "w24"
    | R.W25 -> "w25"
    | R.W26 -> "w26"
    | R.W27 -> "w27"
    | R.W28 -> "w28"
    | R.W29 -> "w29"
    | R.W30 -> "w30"
    | R.WZR -> "wzr"
    | R.SP -> "sp"
    | R.WSP -> "wsp"
    | R.PC -> "pc"
    | R.V0 -> "v0"
    | R.V1 -> "v1"
    | R.V2 -> "v2"
    | R.V3 -> "v3"
    | R.V4 -> "v4"
    | R.V5 -> "v5"
    | R.V6 -> "v6"
    | R.V7 -> "v7"
    | R.V8 -> "v8"
    | R.V9 -> "v9"
    | R.V10 -> "v10"
    | R.V11 -> "v11"
    | R.V12 -> "v12"
    | R.V13 -> "v13"
    | R.V14 -> "v14"
    | R.V15 -> "v15"
    | R.V16 -> "v16"
    | R.V17 -> "v17"
    | R.V18 -> "v18"
    | R.V19 -> "v19"
    | R.V20 -> "v20"
    | R.V21 -> "v21"
    | R.V22 -> "v22"
    | R.V23 -> "v23"
    | R.V24 -> "v24"
    | R.V25 -> "v25"
    | R.V26 -> "v26"
    | R.V27 -> "v27"
    | R.V28 -> "v28"
    | R.V29 -> "v29"
    | R.V30 -> "v30"
    | R.V31 -> "v31"
    | R.B0 -> "b0"
    | R.B1 -> "b1"
    | R.B2 -> "b2"
    | R.B3 -> "b3"
    | R.B4 -> "b4"
    | R.B5 -> "b5"
    | R.B6 -> "b6"
    | R.B7 -> "b7"
    | R.B8 -> "b8"
    | R.B9 -> "b9"
    | R.B10 -> "b10"
    | R.B11 -> "b11"
    | R.B12 -> "b12"
    | R.B13 -> "b13"
    | R.B14 -> "b14"
    | R.B15 -> "b15"
    | R.B16 -> "b16"
    | R.B17 -> "b17"
    | R.B18 -> "b18"
    | R.B19 -> "b19"
    | R.B20 -> "b20"
    | R.B21 -> "b21"
    | R.B22 -> "b22"
    | R.B23 -> "b23"
    | R.B24 -> "b24"
    | R.B25 -> "b25"
    | R.B26 -> "b26"
    | R.B27 -> "b27"
    | R.B28 -> "b28"
    | R.B29 -> "b29"
    | R.B30 -> "b30"
    | R.B31 -> "b31"
    | R.H0 -> "h0"
    | R.H1 -> "h1"
    | R.H2 -> "h2"
    | R.H3 -> "h3"
    | R.H4 -> "h4"
    | R.H5 -> "h5"
    | R.H6 -> "h6"
    | R.H7 -> "h7"
    | R.H8 -> "h8"
    | R.H9 -> "h9"
    | R.H10 -> "h10"
    | R.H11 -> "h11"
    | R.H12 -> "h12"
    | R.H13 -> "h13"
    | R.H14 -> "h14"
    | R.H15 -> "h15"
    | R.H16 -> "h16"
    | R.H17 -> "h17"
    | R.H18 -> "h18"
    | R.H19 -> "h19"
    | R.H20 -> "h20"
    | R.H21 -> "h21"
    | R.H22 -> "h22"
    | R.H23 -> "h23"
    | R.H24 -> "h24"
    | R.H25 -> "h25"
    | R.H26 -> "h26"
    | R.H27 -> "h27"
    | R.H28 -> "h28"
    | R.H29 -> "h29"
    | R.H30 -> "h30"
    | R.H31 -> "h31"
    | R.S0 -> "s0"
    | R.S1 -> "s1"
    | R.S2 -> "s2"
    | R.S3 -> "s3"
    | R.S4 -> "s4"
    | R.S5 -> "s5"
    | R.S6 -> "s6"
    | R.S7 -> "s7"
    | R.S8 -> "s8"
    | R.S9 -> "s9"
    | R.S10 -> "s10"
    | R.S11 -> "s11"
    | R.S12 -> "s12"
    | R.S13 -> "s13"
    | R.S14 -> "s14"
    | R.S15 -> "s15"
    | R.S16 -> "s16"
    | R.S17 -> "s17"
    | R.S18 -> "s18"
    | R.S19 -> "s19"
    | R.S20 -> "s20"
    | R.S21 -> "s21"
    | R.S22 -> "s22"
    | R.S23 -> "s23"
    | R.S24 -> "s24"
    | R.S25 -> "s25"
    | R.S26 -> "s26"
    | R.S27 -> "s27"
    | R.S28 -> "s28"
    | R.S29 -> "s29"
    | R.S30 -> "s30"
    | R.S31 -> "s31"
    | R.D0 -> "d0"
    | R.D1 -> "d1"
    | R.D2 -> "d2"
    | R.D3 -> "d3"
    | R.D4 -> "d4"
    | R.D5 -> "d5"
    | R.D6 -> "d6"
    | R.D7 -> "d7"
    | R.D8 -> "d8"
    | R.D9 -> "d9"
    | R.D10 -> "d10"
    | R.D11 -> "d11"
    | R.D12 -> "d12"
    | R.D13 -> "d13"
    | R.D14 -> "d14"
    | R.D15 -> "d15"
    | R.D16 -> "d16"
    | R.D17 -> "d17"
    | R.D18 -> "d18"
    | R.D19 -> "d19"
    | R.D20 -> "d20"
    | R.D21 -> "d21"
    | R.D22 -> "d22"
    | R.D23 -> "d23"
    | R.D24 -> "d24"
    | R.D25 -> "d25"
    | R.D26 -> "d26"
    | R.D27 -> "d27"
    | R.D28 -> "d28"
    | R.D29 -> "d29"
    | R.D30 -> "d30"
    | R.D31 -> "d31"
    | R.Q0 -> "q0"
    | R.Q1 -> "q1"
    | R.Q2 -> "q2"
    | R.Q3 -> "q3"
    | R.Q4 -> "q4"
    | R.Q5 -> "q5"
    | R.Q6 -> "q6"
    | R.Q7 -> "q7"
    | R.Q8 -> "q8"
    | R.Q9 -> "q9"
    | R.Q10 -> "q10"
    | R.Q11 -> "q11"
    | R.Q12 -> "q12"
    | R.Q13 -> "q13"
    | R.Q14 -> "q14"
    | R.Q15 -> "q15"
    | R.Q16 -> "q16"
    | R.Q17 -> "q17"
    | R.Q18 -> "q18"
    | R.Q19 -> "q19"
    | R.Q20 -> "q20"
    | R.Q21 -> "q21"
    | R.Q22 -> "q22"
    | R.Q23 -> "q23"
    | R.Q24 -> "q24"
    | R.Q25 -> "q25"
    | R.Q26 -> "q26"
    | R.Q27 -> "q27"
    | R.Q28 -> "q28"
    | R.Q29 -> "q29"
    | R.Q30 -> "q30"
    | R.Q31 -> "q31"
    | R.V0A -> "v0a"
    | R.V0B -> "v0b"
    | R.V1A -> "v1a"
    | R.V1B -> "v1b"
    | R.V2A -> "v2a"
    | R.V2B -> "v2b"
    | R.V3A -> "v3a"
    | R.V3B -> "v3b"
    | R.V4A -> "v4a"
    | R.V4B -> "v4b"
    | R.V5A -> "v5a"
    | R.V5B -> "v5b"
    | R.V6A -> "v6a"
    | R.V6B -> "v6b"
    | R.V7A -> "v7a"
    | R.V7B -> "v7b"
    | R.V8A -> "v8a"
    | R.V8B -> "v8b"
    | R.V9A -> "v9a"
    | R.V9B -> "v9b"
    | R.V10A -> "v10a"
    | R.V10B -> "v10b"
    | R.V11A -> "v11a"
    | R.V11B -> "v11b"
    | R.V12A -> "v12a"
    | R.V12B -> "v12b"
    | R.V13A -> "v13a"
    | R.V13B -> "v13b"
    | R.V14A -> "v14a"
    | R.V14B -> "v14b"
    | R.V15A -> "v15a"
    | R.V15B -> "v15b"
    | R.V16A -> "v16a"
    | R.V16B -> "v16b"
    | R.V17A -> "v17a"
    | R.V17B -> "v17b"
    | R.V18A -> "v18a"
    | R.V18B -> "v18b"
    | R.V19A -> "v19a"
    | R.V19B -> "v19b"
    | R.V20A -> "v20a"
    | R.V20B -> "v20b"
    | R.V21A -> "v21a"
    | R.V21B -> "v21b"
    | R.V22A -> "v22a"
    | R.V22B -> "v22b"
    | R.V23A -> "v23a"
    | R.V23B -> "v23b"
    | R.V24A -> "v24a"
    | R.V24B -> "v24b"
    | R.V25A -> "v25a"
    | R.V25B -> "v25b"
    | R.V26A -> "v26a"
    | R.V26B -> "v26b"
    | R.V27A -> "v27a"
    | R.V27B -> "v27b"
    | R.V28A -> "v28a"
    | R.V28B -> "v28b"
    | R.V29A -> "v29a"
    | R.V29B -> "v29b"
    | R.V30A -> "v30a"
    | R.V30B -> "v30b"
    | R.V31A -> "v31a"
    | R.V31B -> "v31b"
    | R.C0 -> "c0"
    | R.C1 -> "c1"
    | R.C2 -> "c2"
    | R.C3 -> "c3"
    | R.C4 -> "c4"
    | R.C5 -> "c5"
    | R.C6 -> "c6"
    | R.C7 -> "c7"
    | R.C8 -> "c8"
    | R.C9 -> "c9"
    | R.C10 -> "c10"
    | R.C11 -> "c11"
    | R.C12 -> "c12"
    | R.C13 -> "c13"
    | R.C14 -> "c14"
    | R.C15 -> "c15"
    | R.N -> "n"
    | R.Z -> "z"
    | R.C -> "c"
    | R.V -> "v"
    | R.ACTLREL1 -> "actlr_el1"
    | R.ACTLREL2 -> "actlr_el2"
    | R.ACTLREL3 -> "actlr_el3"
    | R.AFSR0EL1 -> "afsr0_el1"
    | R.AFSR0EL2 -> "afsr0_el2"
    | R.AFSR0EL3 -> "afsr0_el3"
    | R.AFSR1EL1 -> "afsr1_el1"
    | R.AFSR1EL2 -> "afsr1_el2"
    | R.AFSR1EL3 -> "afsr1_el3"
    | R.AIDREL1 -> "aidr_el1"
    | R.AMAIREL1 -> "amair_el1"
    | R.AMAIREL2 -> "amair_el2"
    | R.AMAIREL3 -> "amair_el3"
    | R.CCSIDREL1 -> "ccsidr_el1"
    | R.CLIDREL1 -> "clidr_el1"
    | R.CONTEXTIDREL1 -> "contextidr_el1"
    | R.CPACREL1 -> "cpacr_el1"
    | R.CPTREL2 -> "cptr_el2"
    | R.CPTREL3 -> "cptr_el3"
    | R.CSSELREL1 -> "csselr_el1"
    | R.CTREL0 -> "ctr_el0"
    | R.DACR32EL2 -> "dacr32_el2"
    | R.DCZIDEL0 -> "dczid_el0"
    | R.ESREL1 -> "esr_el1"
    | R.ESREL2 -> "esr_el2"
    | R.ESREL3 -> "esr_el3"
    | R.HPFAREL2 -> "hpfar_el2"
    | R.TPIDREL0 -> "tpidr_el0"
    | R.FPCR -> "fpcr"
    | R.FPSR -> "fpsr"
    | _ -> Utils.impossible ()

  let toRegType = function
    | R.X0 | R.X1 | R.X2 | R.X3 | R.X4 | R.X5 | R.X6 | R.X7 | R.X8 | R.X9
    | R.X10 | R.X11 | R.X12 | R.X13 | R.X14 | R.X15 | R.X16 | R.X17
    | R.X18 | R.X19 | R.X20 | R.X21 | R.X22 | R.X23 | R.X24 | R.X25
    | R.X26 | R.X27 | R.X28 | R.X29 | R.X30 | R.XZR | R.SP | R.PC
    | R.D0 | R.D1 | R.D2 | R.D3 | R.D4 | R.D5 | R.D6 | R.D7 | R.D8 | R.D9
    | R.D10 | R.D11 | R.D12 | R.D13 | R.D14 | R.D15 | R.D16 | R.D17 | R.D18
    | R.D19 | R.D20 | R.D21 | R.D22 | R.D23 | R.D24 | R.D25 | R.D26 | R.D27
    | R.D28 | R.D29 | R.D30 | R.D31
    | R.V12A | R.V12B | R.V13A | R.V13B | R.V14A | R.V14B | R.V15A | R.V15B
    | R.V16A | R.V16B | R.V17A | R.V17B | R.V18A | R.V18B | R.V19A | R.V19B
    | R.V20A | R.V20B | R.V21A | R.V21B | R.V22A | R.V22B | R.V23A | R.V23B
    | R.V24A | R.V24B | R.V25A | R.V25B | R.V26A | R.V26B | R.V27A | R.V27B
    | R.V28A | R.V28B | R.V29A | R.V29B | R.V30A | R.V30B | R.V31A | R.V31B
    | R.FPCR | R.FPSR -> 64<rt>
    | R.V0A | R.V0B | R.V1A | R.V1B | R.V2A | R.V2B | R.V3A | R.V3B
    | R.V4A | R.V4B | R.V5A | R.V5B | R.V6A | R.V6B | R.V7A | R.V7B
    | R.V8A | R.V8B | R.V9A | R.V9B | R.V10A | R.V10B | R.V11A | R.V11B
    | R.W0 | R.W1 | R.W2 | R.W3 | R.W4 | R.W5 | R.W6 | R.W7 | R.W8 | R.W9
    | R.W10 | R.W11 | R.W12 | R.W13 | R.W14 | R.W15 | R.W16 | R.W17 | R.W18
    | R.W19 | R.W20 | R.W21 | R.W22 | R.W23 | R.W24 | R.W25 | R.W26 | R.W27
    | R.W28 | R.W29 | R.W30 | R.WZR | R.WSP
    | R.S0 | R.S1 | R.S2 | R.S3 | R.S4 | R.S5 | R.S6 | R.S7 | R.S8 | R.S9
    | R.S10 | R.S11 | R.S12 | R.S13 | R.S14 | R.S15 | R.S16 | R.S17 | R.S18
    | R.S19 | R.S20 | R.S21 | R.S22 | R.S23 | R.S24 | R.S25 | R.S26 | R.S27
    | R.S28 | R.S29 | R.S30 | R.S31 -> 32<rt>
    | R.H0 | R.H1 | R.H2 | R.H3 | R.H4 | R.H5 | R.H6 | R.H7 | R.H8 | R.H9
    | R.H10 | R.H11 | R.H12 | R.H13 | R.H14 | R.H15 | R.H16 | R.H17 | R.H18
    | R.H19 | R.H20 | R.H21 | R.H22 | R.H23 | R.H24 | R.H25 | R.H26 | R.H27
    | R.H28 | R.H29 | R.H30 | R.H31 -> 16<rt>
    | R.B0 | R.B1 | R.B2 | R.B3 | R.B4 | R.B5 | R.B6 | R.B7 | R.B8 | R.B9
    | R.B10 | R.B11 | R.B12 | R.B13 | R.B14 | R.B15 | R.B16 | R.B17 | R.B18
    | R.B19 | R.B20 | R.B21 | R.B22 | R.B23 | R.B24 | R.B25 | R.B26 | R.B27
    | R.B28 | R.B29 | R.B30 | R.B31 -> 8<rt>
    | R.V0 | R.V1 | R.V2 | R.V3 | R.V4 | R.V5 | R.V6 | R.V7 | R.V8 | R.V9
    | R.V10 | R.V11 | R.V12 | R.V13 | R.V14 | R.V15 | R.V16 | R.V17 | R.V18
    | R.V19 | R.V20 | R.V21 | R.V22 | R.V23 | R.V24 | R.V25 | R.V26 | R.V27
    | R.V28 | R.V29 | R.V30 | R.V31
    | R.Q0 | R.Q1 | R.Q2 | R.Q3 | R.Q4 | R.Q5 | R.Q6 | R.Q7 | R.Q8 | R.Q9
    | R.Q10 | R.Q11 | R.Q12 | R.Q13 | R.Q14 | R.Q15 | R.Q16 | R.Q17 | R.Q18
    | R.Q19 | R.Q20 | R.Q21 | R.Q22 | R.Q23 | R.Q24 | R.Q25 | R.Q26 | R.Q27
    | R.Q28 | R.Q29 | R.Q30 | R.Q31 -> 128<rt>
    | R.N | R.Z | R.C | R.V -> 1<rt>
    | _ -> Utils.impossible ()
