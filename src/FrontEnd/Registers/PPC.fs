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

namespace B2R2.FrontEnd.PPC

open B2R2

/// <namespacedoc>
///   <summary>
///   Contains types and functions for working with the PPC instructions.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents registers for PPC.<para/>
/// </summary>
type Register =
  | R0 = 0x0
  | R1 = 0x1
  | R2 = 0x2
  | R3 = 0x3
  | R4 = 0x4
  | R5 = 0x5
  | R6 = 0x6
  | R7 = 0x7
  | R8 = 0x8
  | R9 = 0x9
  | R10 = 0xA
  | R11 = 0xB
  | R12 = 0xC
  | R13 = 0xD
  | R14 = 0xE
  | R15 = 0xF
  | R16 = 0x10
  | R17 = 0x11
  | R18 = 0x12
  | R19 = 0x13
  | R20 = 0x14
  | R21 = 0x15
  | R22 = 0x16
  | R23 = 0x17
  | R24 = 0x18
  | R25 = 0x19
  | R26 = 0x1A
  | R27 = 0x1B
  | R28 = 0x1C
  | R29 = 0x1D
  | R30 = 0x1E
  | R31 = 0x1F
  | F0 = 0x20
  | F1 = 0x21
  | F2 = 0x22
  | F3 = 0x23
  | F4 = 0x24
  | F5 = 0x25
  | F6 = 0x26
  | F7 = 0x27
  | F8 = 0x28
  | F9 = 0x29
  | F10 = 0x2A
  | F11 = 0x2B
  | F12 = 0x2C
  | F13 = 0x2D
  | F14 = 0x2E
  | F15 = 0x2F
  | F16 = 0x30
  | F17 = 0x31
  | F18 = 0x32
  | F19 = 0x33
  | F20 = 0x34
  | F21 = 0x35
  | F22 = 0x36
  | F23 = 0x37
  | F24 = 0x38
  | F25 = 0x39
  | F26 = 0x3A
  | F27 = 0x3B
  | F28 = 0x3C
  | F29 = 0x3D
  | F30 = 0x3E
  | F31 = 0x3F
  /// CR0 - CR7 is 4bit chunk of CR.
  | CR0 = 0x40
  | CR1 = 0x41
  | CR2 = 0x42
  | CR3 = 0x43
  | CR4 = 0x44
  | CR5 = 0x45
  | CR6 = 0x46
  | CR7 = 0x47
  /// CR0_0 is the 1st 1-bit chunk of CR0.
  | CR0_0 = 0x48
  /// CR0_1 is the 2nd 1-bit chunk of CR0.
  | CR0_1 = 0x49
  /// CR0_2 is the 3rd 1-bit chunk of CR0.
  | CR0_2 = 0x4A
  /// CR0_3 is the 4th 1-bit chunk of CR0.
  | CR0_3 = 0x4B
  /// CR1_0 is the 1st 1-bit chunk of CR1.
  | CR1_0 = 0x4C
  /// CR1_1 is the 2nd 1-bit chunk of CR1.
  | CR1_1 = 0x4D
  /// CR1_2 is the 3rd 1-bit chunk of CR1.
  | CR1_2 = 0x4E
  /// CR1_3 is the 4th 1-bit chunk of CR1.
  | CR1_3 = 0x4F
  /// CR2_0 is the 1st 1-bit chunk of CR2.
  | CR2_0 = 0x50
  /// CR2_1 is the 2nd 1-bit chunk of CR2.
  | CR2_1 = 0x51
  /// CR2_2 is the 3rd 1-bit chunk of CR2.
  | CR2_2 = 0x52
  /// CR2_3 is the 4th 1-bit chunk of CR2.
  | CR2_3 = 0x53
  /// CR3_0 is the 1st 1-bit chunk of CR3.
  | CR3_0 = 0x54
  /// CR3_1 is the 2nd 1-bit chunk of CR3.
  | CR3_1 = 0x55
  /// CR3_2 is the 3rd 1-bit chunk of CR3.
  | CR3_2 = 0x56
  /// CR3_3 is the 4th 1-bit chunk of CR3.
  | CR3_3 = 0x57
  /// CR4_0 is the 1st 1-bit chunk of CR4.
  | CR4_0 = 0x58
  /// CR4_1 is the 2nd 1-bit chunk of CR4.
  | CR4_1 = 0x59
  /// CR4_2 is the 3rd 1-bit chunk of CR4.
  | CR4_2 = 0x5A
  /// CR4_3 is the 4th 1-bit chunk of CR4.
  | CR4_3 = 0x5B
  /// CR5_0 is the 1st 1-bit chunk of CR5.
  | CR5_0 = 0x5C
  /// CR5_1 is the 2nd 1-bit chunk of CR5.
  | CR5_1 = 0x5D
  /// CR5_2 is the 3rd 1-bit chunk of CR5.
  | CR5_2 = 0x5E
  /// CR5_3 is the 4th 1-bit chunk of CR5.
  | CR5_3 = 0x5F
  /// CR6_0 is the 1st 1-bit chunk of CR6.
  | CR6_0 = 0x60
  /// CR6_1 is the 2nd 1-bit chunk of CR6.
  | CR6_1 = 0x61
  /// CR6_2 is the 3rd 1-bit chunk of CR6.
  | CR6_2 = 0x62
  /// CR6_3 is the 4th 1-bit chunk of CR6.
  | CR6_3 = 0x63
  /// CR7_0 is the 1st 1-bit chunk of CR7.
  | CR7_0 = 0x64
  /// CR7_1 is the 2nd 1-bit chunk of CR7.
  | CR7_1 = 0x65
  /// CR7_2 is the 3rd 1-bit chunk of CR7.
  | CR7_2 = 0x66
  /// CR7_3 is the 4th 1-bit chunk of CR7.
  | CR7_3 = 0x67
  /// XER Register.
  | XER = 0x70
  /// LR Register.
  | LR = 0x71
  /// Count Register.
  | CTR = 0x72
  /// FPSCR Register
  | FPSCR = 0x73
  /// Processor Version Register.
  | PVR = 0x74
  /// Pseudo register for Reserve.
  | RES = 0x75
  /// Instruction address register, i.e., the program counter (pseudo-register).
  | IAR = 0x76
  /// Pseudo register: the reserved address of a load-and-reserve (lwarx), for a
  /// value-based exclusive-monitor model. See ExMonVal.
  | ExMonAddr = 0x77
  /// Pseudo register: the memory value at ExMonAddr when lwarx ran, so a later
  /// stwcx. can tell whether the location was written in between.
  | ExMonVal = 0x78
  /// Vector Status and Control Register.
  | VSCR = 0x79
  /// Vector Save/Restore Register.
  | VRSAVE = 0x7A
  (* Each 128-bit vector register is kept as two 64-bit halves, as the
     other ports with wide registers do: the "A" half is the vector's
     high doubleword (PowerPC numbers vector elements from there) and the
     "B" half its low one. *)
  /// V0A is the high 64-bit half of V0.
  | V0A = 0x80
  /// V0B is the low 64-bit half of V0.
  | V0B = 0x81
  /// V1A is the high 64-bit half of V1.
  | V1A = 0x82
  /// V1B is the low 64-bit half of V1.
  | V1B = 0x83
  /// V2A is the high 64-bit half of V2.
  | V2A = 0x84
  /// V2B is the low 64-bit half of V2.
  | V2B = 0x85
  /// V3A is the high 64-bit half of V3.
  | V3A = 0x86
  /// V3B is the low 64-bit half of V3.
  | V3B = 0x87
  /// V4A is the high 64-bit half of V4.
  | V4A = 0x88
  /// V4B is the low 64-bit half of V4.
  | V4B = 0x89
  /// V5A is the high 64-bit half of V5.
  | V5A = 0x8A
  /// V5B is the low 64-bit half of V5.
  | V5B = 0x8B
  /// V6A is the high 64-bit half of V6.
  | V6A = 0x8C
  /// V6B is the low 64-bit half of V6.
  | V6B = 0x8D
  /// V7A is the high 64-bit half of V7.
  | V7A = 0x8E
  /// V7B is the low 64-bit half of V7.
  | V7B = 0x8F
  /// V8A is the high 64-bit half of V8.
  | V8A = 0x90
  /// V8B is the low 64-bit half of V8.
  | V8B = 0x91
  /// V9A is the high 64-bit half of V9.
  | V9A = 0x92
  /// V9B is the low 64-bit half of V9.
  | V9B = 0x93
  /// V10A is the high 64-bit half of V10.
  | V10A = 0x94
  /// V10B is the low 64-bit half of V10.
  | V10B = 0x95
  /// V11A is the high 64-bit half of V11.
  | V11A = 0x96
  /// V11B is the low 64-bit half of V11.
  | V11B = 0x97
  /// V12A is the high 64-bit half of V12.
  | V12A = 0x98
  /// V12B is the low 64-bit half of V12.
  | V12B = 0x99
  /// V13A is the high 64-bit half of V13.
  | V13A = 0x9A
  /// V13B is the low 64-bit half of V13.
  | V13B = 0x9B
  /// V14A is the high 64-bit half of V14.
  | V14A = 0x9C
  /// V14B is the low 64-bit half of V14.
  | V14B = 0x9D
  /// V15A is the high 64-bit half of V15.
  | V15A = 0x9E
  /// V15B is the low 64-bit half of V15.
  | V15B = 0x9F
  /// V16A is the high 64-bit half of V16.
  | V16A = 0xA0
  /// V16B is the low 64-bit half of V16.
  | V16B = 0xA1
  /// V17A is the high 64-bit half of V17.
  | V17A = 0xA2
  /// V17B is the low 64-bit half of V17.
  | V17B = 0xA3
  /// V18A is the high 64-bit half of V18.
  | V18A = 0xA4
  /// V18B is the low 64-bit half of V18.
  | V18B = 0xA5
  /// V19A is the high 64-bit half of V19.
  | V19A = 0xA6
  /// V19B is the low 64-bit half of V19.
  | V19B = 0xA7
  /// V20A is the high 64-bit half of V20.
  | V20A = 0xA8
  /// V20B is the low 64-bit half of V20.
  | V20B = 0xA9
  /// V21A is the high 64-bit half of V21.
  | V21A = 0xAA
  /// V21B is the low 64-bit half of V21.
  | V21B = 0xAB
  /// V22A is the high 64-bit half of V22.
  | V22A = 0xAC
  /// V22B is the low 64-bit half of V22.
  | V22B = 0xAD
  /// V23A is the high 64-bit half of V23.
  | V23A = 0xAE
  /// V23B is the low 64-bit half of V23.
  | V23B = 0xAF
  /// V24A is the high 64-bit half of V24.
  | V24A = 0xB0
  /// V24B is the low 64-bit half of V24.
  | V24B = 0xB1
  /// V25A is the high 64-bit half of V25.
  | V25A = 0xB2
  /// V25B is the low 64-bit half of V25.
  | V25B = 0xB3
  /// V26A is the high 64-bit half of V26.
  | V26A = 0xB4
  /// V26B is the low 64-bit half of V26.
  | V26B = 0xB5
  /// V27A is the high 64-bit half of V27.
  | V27A = 0xB6
  /// V27B is the low 64-bit half of V27.
  | V27B = 0xB7
  /// V28A is the high 64-bit half of V28.
  | V28A = 0xB8
  /// V28B is the low 64-bit half of V28.
  | V28B = 0xB9
  /// V29A is the high 64-bit half of V29.
  | V29A = 0xBA
  /// V29B is the low 64-bit half of V29.
  | V29B = 0xBB
  /// V30A is the high 64-bit half of V30.
  | V30A = 0xBC
  /// V30B is the low 64-bit half of V30.
  | V30B = 0xBD
  /// V31A is the high 64-bit half of V31.
  | V31A = 0xBE
  /// V31B is the low 64-bit half of V31.
  | V31B = 0xBF
  (* VSX widens each floating-point register to 128 bits: VSR0-31 keep the
     FPR in their high doubleword and hold the low one here, while VSR32-63
     are the vector registers V0-V31 outright. *)
  /// VSRL0 is the low 64-bit half of VSR0, whose high half is F0.
  | VSRL0 = 0xC0
  /// VSRL1 is the low 64-bit half of VSR1, whose high half is F1.
  | VSRL1 = 0xC1
  /// VSRL2 is the low 64-bit half of VSR2, whose high half is F2.
  | VSRL2 = 0xC2
  /// VSRL3 is the low 64-bit half of VSR3, whose high half is F3.
  | VSRL3 = 0xC3
  /// VSRL4 is the low 64-bit half of VSR4, whose high half is F4.
  | VSRL4 = 0xC4
  /// VSRL5 is the low 64-bit half of VSR5, whose high half is F5.
  | VSRL5 = 0xC5
  /// VSRL6 is the low 64-bit half of VSR6, whose high half is F6.
  | VSRL6 = 0xC6
  /// VSRL7 is the low 64-bit half of VSR7, whose high half is F7.
  | VSRL7 = 0xC7
  /// VSRL8 is the low 64-bit half of VSR8, whose high half is F8.
  | VSRL8 = 0xC8
  /// VSRL9 is the low 64-bit half of VSR9, whose high half is F9.
  | VSRL9 = 0xC9
  /// VSRL10 is the low 64-bit half of VSR10, whose high half is F10.
  | VSRL10 = 0xCA
  /// VSRL11 is the low 64-bit half of VSR11, whose high half is F11.
  | VSRL11 = 0xCB
  /// VSRL12 is the low 64-bit half of VSR12, whose high half is F12.
  | VSRL12 = 0xCC
  /// VSRL13 is the low 64-bit half of VSR13, whose high half is F13.
  | VSRL13 = 0xCD
  /// VSRL14 is the low 64-bit half of VSR14, whose high half is F14.
  | VSRL14 = 0xCE
  /// VSRL15 is the low 64-bit half of VSR15, whose high half is F15.
  | VSRL15 = 0xCF
  /// VSRL16 is the low 64-bit half of VSR16, whose high half is F16.
  | VSRL16 = 0xD0
  /// VSRL17 is the low 64-bit half of VSR17, whose high half is F17.
  | VSRL17 = 0xD1
  /// VSRL18 is the low 64-bit half of VSR18, whose high half is F18.
  | VSRL18 = 0xD2
  /// VSRL19 is the low 64-bit half of VSR19, whose high half is F19.
  | VSRL19 = 0xD3
  /// VSRL20 is the low 64-bit half of VSR20, whose high half is F20.
  | VSRL20 = 0xD4
  /// VSRL21 is the low 64-bit half of VSR21, whose high half is F21.
  | VSRL21 = 0xD5
  /// VSRL22 is the low 64-bit half of VSR22, whose high half is F22.
  | VSRL22 = 0xD6
  /// VSRL23 is the low 64-bit half of VSR23, whose high half is F23.
  | VSRL23 = 0xD7
  /// VSRL24 is the low 64-bit half of VSR24, whose high half is F24.
  | VSRL24 = 0xD8
  /// VSRL25 is the low 64-bit half of VSR25, whose high half is F25.
  | VSRL25 = 0xD9
  /// VSRL26 is the low 64-bit half of VSR26, whose high half is F26.
  | VSRL26 = 0xDA
  /// VSRL27 is the low 64-bit half of VSR27, whose high half is F27.
  | VSRL27 = 0xDB
  /// VSRL28 is the low 64-bit half of VSR28, whose high half is F28.
  | VSRL28 = 0xDC
  /// VSRL29 is the low 64-bit half of VSR29, whose high half is F29.
  | VSRL29 = 0xDD
  /// VSRL30 is the low 64-bit half of VSR30, whose high half is F30.
  | VSRL30 = 0xDE
  /// VSRL31 is the low 64-bit half of VSR31, whose high half is F31.
  | VSRL31 = 0xDF

/// Provides functions to handle PPC registers.
module Register =
  /// Returns the PPC register from a register ID.
  [<CompiledName "OfRegID">]
  let inline ofRegID (rid: RegisterID): Register =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Returns the PPC register from a string representation.
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant() with
    | "r0" -> Register.R0
    | "r1" -> Register.R1
    | "r2" -> Register.R2
    | "r3" -> Register.R3
    | "r4" -> Register.R4
    | "r5" -> Register.R5
    | "r6" -> Register.R6
    | "r7" -> Register.R7
    | "r8" -> Register.R8
    | "r9" -> Register.R9
    | "r10" -> Register.R10
    | "r11" -> Register.R11
    | "r12" -> Register.R12
    | "r13" -> Register.R13
    | "r14" -> Register.R14
    | "r15" -> Register.R15
    | "r16" -> Register.R16
    | "r17" -> Register.R17
    | "r18" -> Register.R18
    | "r19" -> Register.R19
    | "r20" -> Register.R20
    | "r21" -> Register.R21
    | "r22" -> Register.R22
    | "r23" -> Register.R23
    | "r24" -> Register.R24
    | "r25" -> Register.R25
    | "r26" -> Register.R26
    | "r27" -> Register.R27
    | "r28" -> Register.R28
    | "r29" -> Register.R29
    | "r30" -> Register.R30
    | "r31" -> Register.R31
    | "f0" -> Register.F0
    | "f1" -> Register.F1
    | "f2" -> Register.F2
    | "f3" -> Register.F3
    | "f4" -> Register.F4
    | "f5" -> Register.F5
    | "f6" -> Register.F6
    | "f7" -> Register.F7
    | "f8" -> Register.F8
    | "f9" -> Register.F9
    | "f10" -> Register.F10
    | "f11" -> Register.F11
    | "f12" -> Register.F12
    | "f13" -> Register.F13
    | "f14" -> Register.F14
    | "f15" -> Register.F15
    | "f16" -> Register.F16
    | "f17" -> Register.F17
    | "f18" -> Register.F18
    | "f19" -> Register.F19
    | "f20" -> Register.F20
    | "f21" -> Register.F21
    | "f22" -> Register.F22
    | "f23" -> Register.F23
    | "f24" -> Register.F24
    | "f25" -> Register.F25
    | "f26" -> Register.F26
    | "f27" -> Register.F27
    | "f28" -> Register.F28
    | "f29" -> Register.F29
    | "f30" -> Register.F30
    | "f31" -> Register.F31
    | "cr0" -> Register.CR0
    | "cr1" -> Register.CR1
    | "cr2" -> Register.CR2
    | "cr3" -> Register.CR3
    | "cr4" -> Register.CR4
    | "cr5" -> Register.CR5
    | "cr6" -> Register.CR6
    | "cr7" -> Register.CR7
    | "cr0_0" -> Register.CR0_0
    | "cr0_1" -> Register.CR0_1
    | "cr0_2" -> Register.CR0_2
    | "cr0_3" -> Register.CR0_3
    | "cr1_0" -> Register.CR1_0
    | "cr1_1" -> Register.CR1_1
    | "cr1_2" -> Register.CR1_2
    | "cr1_3" -> Register.CR1_3
    | "cr2_0" -> Register.CR2_0
    | "cr2_1" -> Register.CR2_1
    | "cr2_2" -> Register.CR2_2
    | "cr2_3" -> Register.CR2_3
    | "cr3_0" -> Register.CR3_0
    | "cr3_1" -> Register.CR3_1
    | "cr3_2" -> Register.CR3_2
    | "cr3_3" -> Register.CR3_3
    | "cr4_0" -> Register.CR4_0
    | "cr4_1" -> Register.CR4_1
    | "cr4_2" -> Register.CR4_2
    | "cr4_3" -> Register.CR4_3
    | "cr5_0" -> Register.CR5_0
    | "cr5_1" -> Register.CR5_1
    | "cr5_2" -> Register.CR5_2
    | "cr5_3" -> Register.CR5_3
    | "cr6_0" -> Register.CR6_0
    | "cr6_1" -> Register.CR6_1
    | "cr6_2" -> Register.CR6_2
    | "cr6_3" -> Register.CR6_3
    | "cr7_0" -> Register.CR7_0
    | "cr7_1" -> Register.CR7_1
    | "cr7_2" -> Register.CR7_2
    | "cr7_3" -> Register.CR7_3
    | "res" -> Register.RES
    | "iar" -> Register.IAR
    | "exmonaddr" -> Register.ExMonAddr
    | "exmonval" -> Register.ExMonVal
    | "vscr" -> Register.VSCR
    | "vrsave" -> Register.VRSAVE
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
    | "vsrl0" -> Register.VSRL0
    | "vsrl1" -> Register.VSRL1
    | "vsrl2" -> Register.VSRL2
    | "vsrl3" -> Register.VSRL3
    | "vsrl4" -> Register.VSRL4
    | "vsrl5" -> Register.VSRL5
    | "vsrl6" -> Register.VSRL6
    | "vsrl7" -> Register.VSRL7
    | "vsrl8" -> Register.VSRL8
    | "vsrl9" -> Register.VSRL9
    | "vsrl10" -> Register.VSRL10
    | "vsrl11" -> Register.VSRL11
    | "vsrl12" -> Register.VSRL12
    | "vsrl13" -> Register.VSRL13
    | "vsrl14" -> Register.VSRL14
    | "vsrl15" -> Register.VSRL15
    | "vsrl16" -> Register.VSRL16
    | "vsrl17" -> Register.VSRL17
    | "vsrl18" -> Register.VSRL18
    | "vsrl19" -> Register.VSRL19
    | "vsrl20" -> Register.VSRL20
    | "vsrl21" -> Register.VSRL21
    | "vsrl22" -> Register.VSRL22
    | "vsrl23" -> Register.VSRL23
    | "vsrl24" -> Register.VSRL24
    | "vsrl25" -> Register.VSRL25
    | "vsrl26" -> Register.VSRL26
    | "vsrl27" -> Register.VSRL27
    | "vsrl28" -> Register.VSRL28
    | "vsrl29" -> Register.VSRL29
    | "vsrl30" -> Register.VSRL30
    | "vsrl31" -> Register.VSRL31
    | _ -> Terminator.impossible ()

  /// Returns the register ID of a PPC register.
  [<CompiledName "ToRegID">]
  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue(reg) |> RegisterID.create

  /// Returns the string representation of a PPC register.
  [<CompiledName "ToString">]
  let toString reg =
    match reg with
    | Register.R0 -> "r0"
    | Register.R1 -> "r1"
    | Register.R2 -> "r2"
    | Register.R3 -> "r3"
    | Register.R4 -> "r4"
    | Register.R5 -> "r5"
    | Register.R6 -> "r6"
    | Register.R7 -> "r7"
    | Register.R8 -> "r8"
    | Register.R9 -> "r9"
    | Register.R10 -> "r10"
    | Register.R11 -> "r11"
    | Register.R12 -> "r12"
    | Register.R13 -> "r13"
    | Register.R14 -> "r14"
    | Register.R15 -> "r15"
    | Register.R16 -> "r16"
    | Register.R17 -> "r17"
    | Register.R18 -> "r18"
    | Register.R19 -> "r19"
    | Register.R20 -> "r20"
    | Register.R21 -> "r21"
    | Register.R22 -> "r22"
    | Register.R23 -> "r23"
    | Register.R24 -> "r24"
    | Register.R25 -> "r25"
    | Register.R26 -> "r26"
    | Register.R27 -> "r27"
    | Register.R28 -> "r28"
    | Register.R29 -> "r29"
    | Register.R30 -> "r30"
    | Register.R31 -> "r31"
    | Register.F0 -> "f0"
    | Register.F1 -> "f1"
    | Register.F2 -> "f2"
    | Register.F3 -> "f3"
    | Register.F4 -> "f4"
    | Register.F5 -> "f5"
    | Register.F6 -> "f6"
    | Register.F7 -> "f7"
    | Register.F8 -> "f8"
    | Register.F9 -> "f9"
    | Register.F10 -> "f10"
    | Register.F11 -> "f11"
    | Register.F12 -> "f12"
    | Register.F13 -> "f13"
    | Register.F14 -> "f14"
    | Register.F15 -> "f15"
    | Register.F16 -> "f16"
    | Register.F17 -> "f17"
    | Register.F18 -> "f18"
    | Register.F19 -> "f19"
    | Register.F20 -> "f20"
    | Register.F21 -> "f21"
    | Register.F22 -> "f22"
    | Register.F23 -> "f23"
    | Register.F24 -> "f24"
    | Register.F25 -> "f25"
    | Register.F26 -> "f26"
    | Register.F27 -> "f27"
    | Register.F28 -> "f28"
    | Register.F29 -> "f29"
    | Register.F30 -> "f30"
    | Register.F31 -> "f31"
    | Register.CR0 -> "cr0"
    | Register.CR1 -> "cr1"
    | Register.CR2 -> "cr2"
    | Register.CR3 -> "cr3"
    | Register.CR4 -> "cr4"
    | Register.CR5 -> "cr5"
    | Register.CR6 -> "cr6"
    | Register.CR7 -> "cr7"
    | Register.CR0_0 -> "cr0_0"
    | Register.CR0_1 -> "cr0_1"
    | Register.CR0_2 -> "cr0_2"
    | Register.CR0_3 -> "cr0_3"
    | Register.CR1_0 -> "cr1_0"
    | Register.CR1_1 -> "cr1_1"
    | Register.CR1_2 -> "cr1_2"
    | Register.CR1_3 -> "cr1_3"
    | Register.CR2_0 -> "cr2_0"
    | Register.CR2_1 -> "cr2_1"
    | Register.CR2_2 -> "cr2_2"
    | Register.CR2_3 -> "cr2_3"
    | Register.CR3_0 -> "cr3_0"
    | Register.CR3_1 -> "cr3_1"
    | Register.CR3_2 -> "cr3_2"
    | Register.CR3_3 -> "cr3_3"
    | Register.CR4_0 -> "cr4_0"
    | Register.CR4_1 -> "cr4_1"
    | Register.CR4_2 -> "cr4_2"
    | Register.CR4_3 -> "cr4_3"
    | Register.CR5_0 -> "cr5_0"
    | Register.CR5_1 -> "cr5_1"
    | Register.CR5_2 -> "cr5_2"
    | Register.CR5_3 -> "cr5_3"
    | Register.CR6_0 -> "cr6_0"
    | Register.CR6_1 -> "cr6_1"
    | Register.CR6_2 -> "cr6_2"
    | Register.CR6_3 -> "cr6_3"
    | Register.CR7_0 -> "cr7_0"
    | Register.CR7_1 -> "cr7_1"
    | Register.CR7_2 -> "cr7_2"
    | Register.CR7_3 -> "cr7_3"
    | Register.RES -> "res"
    | Register.IAR -> "iar"
    | Register.ExMonAddr -> "exmonaddr"
    | Register.ExMonVal -> "exmonval"
    | Register.VSCR -> "vscr"
    | Register.VRSAVE -> "vrsave"
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
    | Register.VSRL0 -> "vsrl0"
    | Register.VSRL1 -> "vsrl1"
    | Register.VSRL2 -> "vsrl2"
    | Register.VSRL3 -> "vsrl3"
    | Register.VSRL4 -> "vsrl4"
    | Register.VSRL5 -> "vsrl5"
    | Register.VSRL6 -> "vsrl6"
    | Register.VSRL7 -> "vsrl7"
    | Register.VSRL8 -> "vsrl8"
    | Register.VSRL9 -> "vsrl9"
    | Register.VSRL10 -> "vsrl10"
    | Register.VSRL11 -> "vsrl11"
    | Register.VSRL12 -> "vsrl12"
    | Register.VSRL13 -> "vsrl13"
    | Register.VSRL14 -> "vsrl14"
    | Register.VSRL15 -> "vsrl15"
    | Register.VSRL16 -> "vsrl16"
    | Register.VSRL17 -> "vsrl17"
    | Register.VSRL18 -> "vsrl18"
    | Register.VSRL19 -> "vsrl19"
    | Register.VSRL20 -> "vsrl20"
    | Register.VSRL21 -> "vsrl21"
    | Register.VSRL22 -> "vsrl22"
    | Register.VSRL23 -> "vsrl23"
    | Register.VSRL24 -> "vsrl24"
    | Register.VSRL25 -> "vsrl25"
    | Register.VSRL26 -> "vsrl26"
    | Register.VSRL27 -> "vsrl27"
    | Register.VSRL28 -> "vsrl28"
    | Register.VSRL29 -> "vsrl29"
    | Register.VSRL30 -> "vsrl30"
    | Register.VSRL31 -> "vsrl31"
    | _ -> Terminator.impossible ()
