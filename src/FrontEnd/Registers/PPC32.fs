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

namespace B2R2.FrontEnd.PPC32

open B2R2

/// <summary>
/// Registers for PPC32.<para/>
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

/// Helper module for PPC32 registers.
module Register =
  /// Get the PPC32 register from a register ID.
  [<CompiledName "OfRegID">]
  let inline ofRegID (rid: RegisterID): Register =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Get the PPC32 register from a string representation.
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant () with
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
    | _ -> Terminator.impossible ()

  /// Get the register ID of a PPC32 register.
  [<CompiledName "ToRegID">]
  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  /// Get the string representation of a PPC32 register.
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
    | _ -> Terminator.impossible ()
