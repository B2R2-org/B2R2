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

namespace B2R2.FrontEnd.S390

open B2R2

/// <namespacedoc>
///   <summary>
///   Contains types and functions for working with the S390/S390x instructions.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents registers for S390.<para/>
/// </summary>
type Register =
  | R0 = 0
  | R1 = 1
  | R2 = 2
  | R3 = 3
  | R4 = 4
  | R5 = 5
  | R6 = 6
  | R7 = 7
  | R8 = 8
  | R9 = 9
  | R10 = 10
  | R11 = 11
  | R12 = 12
  | R13 = 13
  | R14 = 14
  | R15 = 15
  | FPR0 = 16
  | FPR1 = 17
  | FPR2 = 18
  | FPR3 = 19
  | FPR4 = 20
  | FPR5 = 21
  | FPR6 = 22
  | FPR7 = 23
  | FPR8 = 24
  | FPR9 = 25
  | FPR10 = 26
  | FPR11 = 27
  | FPR12 = 28
  | FPR13 = 29
  | FPR14 = 30
  | FPR15 = 31
  | FPC = 32
  | VR0 = 33
  | VR1 = 34
  | VR2 = 35
  | VR3 = 36
  | VR4 = 37
  | VR5 = 38
  | VR6 = 39
  | VR7 = 40
  | VR8 = 41
  | VR9 = 42
  | VR10 = 43
  | VR11 = 44
  | VR12 = 45
  | VR13 = 46
  | VR14 = 47
  | VR15 = 48
  | VR16 = 49
  | VR17 = 50
  | VR18 = 51
  | VR19 = 52
  | VR20 = 53
  | VR21 = 54
  | VR22 = 55
  | VR23 = 56
  | VR24 = 57
  | VR25 = 58
  | VR26 = 59
  | VR27 = 60
  | VR28 = 61
  | VR29 = 62
  | VR30 = 63
  | VR31 = 64
  | CR0 = 65
  | CR1 = 66
  | CR2 = 67
  | CR3 = 68
  | CR4 = 69
  | CR5 = 70
  | CR6 = 71
  | CR7 = 72
  | CR8 = 73
  | CR9 = 74
  | CR10 = 75
  | CR11 = 76
  | CR12 = 77
  | CR13 = 78
  | CR14 = 79
  | CR15 = 80
  | AR0 = 81
  | AR1 = 82
  | AR2 = 83
  | AR3 = 84
  | AR4 = 85
  | AR5 = 86
  | AR6 = 87
  | AR7 = 88
  | AR8 = 89
  | AR9 = 90
  | AR10 = 91
  | AR11 = 92
  | AR12 = 93
  | AR13 = 94
  | AR14 = 95
  | AR15 = 96
  | BEAR = 97
  | PSW = 98
  /// The instruction address the PSW carries. Modelled on its own, rather than
  /// as the second doubleword of PSW, because it is what every control transfer
  /// writes and what an emulator reads as the program counter, and because the
  /// PSW as a whole is wider than a machine word.
  | PC = 99
  /// The PSW condition code (PSW{CC}), a value of 0 to 3 that nearly every
  /// arithmetic, compare, and test instruction sets and every branch-on-
  /// condition mask selects on. Modelled on its own for the same reason.
  | CC = 100
  /// The interruption code an SVC hands the supervisor: the instruction's own
  /// immediate, which names the system call whenever it is not zero (a zero
  /// immediate means the number is in R1 instead). Real hardware leaves it in
  /// the low-storage area the kernel reads; there is no such storage here, so
  /// it is kept as a register of its own rather than in one the guest owns.
  | SVCCODE = 101
  (* The vector registers are 128 bits wide, which is wider than a register a
     LowUIR expression can name, so each is modelled as two halves. The left
     half of the first sixteen is not a register of its own: the architecture
     makes FPR0 to FPR15 exactly those halves, and a program that writes a
     floating-point register and reads the vector one must see the same bits.
     Only the right halves of those sixteen, and both halves of the upper
     sixteen, need names here. *)
  /// The right half of VR0, whose left half is FPR0.
  | VR0L = 102
  /// The right half of VR1, whose left half is FPR1.
  | VR1L = 103
  /// The right half of VR2, whose left half is FPR2.
  | VR2L = 104
  /// The right half of VR3, whose left half is FPR3.
  | VR3L = 105
  /// The right half of VR4, whose left half is FPR4.
  | VR4L = 106
  /// The right half of VR5, whose left half is FPR5.
  | VR5L = 107
  /// The right half of VR6, whose left half is FPR6.
  | VR6L = 108
  /// The right half of VR7, whose left half is FPR7.
  | VR7L = 109
  /// The right half of VR8, whose left half is FPR8.
  | VR8L = 110
  /// The right half of VR9, whose left half is FPR9.
  | VR9L = 111
  /// The right half of VR10, whose left half is FPR10.
  | VR10L = 112
  /// The right half of VR11, whose left half is FPR11.
  | VR11L = 113
  /// The right half of VR12, whose left half is FPR12.
  | VR12L = 114
  /// The right half of VR13, whose left half is FPR13.
  | VR13L = 115
  /// The right half of VR14, whose left half is FPR14.
  | VR14L = 116
  /// The right half of VR15, whose left half is FPR15.
  | VR15L = 117
  /// The left half of VR16.
  | VR16H = 118
  /// The right half of VR16.
  | VR16L = 119
  /// The left half of VR17.
  | VR17H = 120
  /// The right half of VR17.
  | VR17L = 121
  /// The left half of VR18.
  | VR18H = 122
  /// The right half of VR18.
  | VR18L = 123
  /// The left half of VR19.
  | VR19H = 124
  /// The right half of VR19.
  | VR19L = 125
  /// The left half of VR20.
  | VR20H = 126
  /// The right half of VR20.
  | VR20L = 127
  /// The left half of VR21.
  | VR21H = 128
  /// The right half of VR21.
  | VR21L = 129
  /// The left half of VR22.
  | VR22H = 130
  /// The right half of VR22.
  | VR22L = 131
  /// The left half of VR23.
  | VR23H = 132
  /// The right half of VR23.
  | VR23L = 133
  /// The left half of VR24.
  | VR24H = 134
  /// The right half of VR24.
  | VR24L = 135
  /// The left half of VR25.
  | VR25H = 136
  /// The right half of VR25.
  | VR25L = 137
  /// The left half of VR26.
  | VR26H = 138
  /// The right half of VR26.
  | VR26L = 139
  /// The left half of VR27.
  | VR27H = 140
  /// The right half of VR27.
  | VR27L = 141
  /// The left half of VR28.
  | VR28H = 142
  /// The right half of VR28.
  | VR28L = 143
  /// The left half of VR29.
  | VR29H = 144
  /// The right half of VR29.
  | VR29L = 145
  /// The left half of VR30.
  | VR30H = 146
  /// The right half of VR30.
  | VR30L = 147
  /// The left half of VR31.
  | VR31H = 148
  /// The right half of VR31.
  | VR31L = 149

/// Provides functions to handle S390 registers.
module Register =
  /// Returns the S390 register from a register ID.
  [<CompiledName "OfRegID">]
  let inline ofRegID (rid: RegisterID): Register =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Returns the S390 register from a string representation.
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
    | "fpr0" -> Register.FPR0
    | "fpr1" -> Register.FPR1
    | "fpr2" -> Register.FPR2
    | "fpr3" -> Register.FPR3
    | "fpr4" -> Register.FPR4
    | "fpr5" -> Register.FPR5
    | "fpr6" -> Register.FPR6
    | "fpr7" -> Register.FPR7
    | "fpr8" -> Register.FPR8
    | "fpr9" -> Register.FPR9
    | "fpr10" -> Register.FPR10
    | "fpr11" -> Register.FPR11
    | "fpr12" -> Register.FPR12
    | "fpr13" -> Register.FPR13
    | "fpr14" -> Register.FPR14
    | "fpr15" -> Register.FPR15
    | "fpc" -> Register.FPC
    | "vr0" -> Register.VR0
    | "vr1" -> Register.VR1
    | "vr2" -> Register.VR2
    | "vr3" -> Register.VR3
    | "vr4" -> Register.VR4
    | "vr5" -> Register.VR5
    | "vr6" -> Register.VR6
    | "vr7" -> Register.VR7
    | "vr8" -> Register.VR8
    | "vr9" -> Register.VR9
    | "vr10" -> Register.VR10
    | "vr11" -> Register.VR11
    | "vr12" -> Register.VR12
    | "vr13" -> Register.VR13
    | "vr14" -> Register.VR14
    | "vr15" -> Register.VR15
    | "vr16" -> Register.VR16
    | "vr17" -> Register.VR17
    | "vr18" -> Register.VR18
    | "vr19" -> Register.VR19
    | "vr20" -> Register.VR20
    | "vr21" -> Register.VR21
    | "vr22" -> Register.VR22
    | "vr23" -> Register.VR23
    | "vr24" -> Register.VR24
    | "vr25" -> Register.VR25
    | "vr26" -> Register.VR26
    | "vr27" -> Register.VR27
    | "vr28" -> Register.VR28
    | "vr29" -> Register.VR29
    | "vr30" -> Register.VR30
    | "vr31" -> Register.VR31
    | "cr0" -> Register.CR0
    | "cr1" -> Register.CR1
    | "cr2" -> Register.CR2
    | "cr3" -> Register.CR3
    | "cr4" -> Register.CR4
    | "cr5" -> Register.CR5
    | "cr6" -> Register.CR6
    | "cr7" -> Register.CR7
    | "cr8" -> Register.CR8
    | "cr9" -> Register.CR9
    | "cr10" -> Register.CR10
    | "cr11" -> Register.CR11
    | "cr12" -> Register.CR12
    | "cr13" -> Register.CR13
    | "cr14" -> Register.CR14
    | "cr15" -> Register.CR15
    | "ar0" -> Register.AR0
    | "ar1" -> Register.AR1
    | "ar2" -> Register.AR2
    | "ar3" -> Register.AR3
    | "ar4" -> Register.AR4
    | "ar5" -> Register.AR5
    | "ar6" -> Register.AR6
    | "ar7" -> Register.AR7
    | "ar8" -> Register.AR8
    | "ar9" -> Register.AR9
    | "ar10" -> Register.AR10
    | "ar11" -> Register.AR11
    | "ar12" -> Register.AR12
    | "ar13" -> Register.AR13
    | "ar14" -> Register.AR14
    | "ar15" -> Register.AR15
    | "bear" -> Register.BEAR
    | "psw" -> Register.PSW
    | "pc" -> Register.PC
    | "cc" -> Register.CC
    | "svccode" -> Register.SVCCODE
    | "vr0l" -> Register.VR0L
    | "vr1l" -> Register.VR1L
    | "vr2l" -> Register.VR2L
    | "vr3l" -> Register.VR3L
    | "vr4l" -> Register.VR4L
    | "vr5l" -> Register.VR5L
    | "vr6l" -> Register.VR6L
    | "vr7l" -> Register.VR7L
    | "vr8l" -> Register.VR8L
    | "vr9l" -> Register.VR9L
    | "vr10l" -> Register.VR10L
    | "vr11l" -> Register.VR11L
    | "vr12l" -> Register.VR12L
    | "vr13l" -> Register.VR13L
    | "vr14l" -> Register.VR14L
    | "vr15l" -> Register.VR15L
    | "vr16h" -> Register.VR16H
    | "vr16l" -> Register.VR16L
    | "vr17h" -> Register.VR17H
    | "vr17l" -> Register.VR17L
    | "vr18h" -> Register.VR18H
    | "vr18l" -> Register.VR18L
    | "vr19h" -> Register.VR19H
    | "vr19l" -> Register.VR19L
    | "vr20h" -> Register.VR20H
    | "vr20l" -> Register.VR20L
    | "vr21h" -> Register.VR21H
    | "vr21l" -> Register.VR21L
    | "vr22h" -> Register.VR22H
    | "vr22l" -> Register.VR22L
    | "vr23h" -> Register.VR23H
    | "vr23l" -> Register.VR23L
    | "vr24h" -> Register.VR24H
    | "vr24l" -> Register.VR24L
    | "vr25h" -> Register.VR25H
    | "vr25l" -> Register.VR25L
    | "vr26h" -> Register.VR26H
    | "vr26l" -> Register.VR26L
    | "vr27h" -> Register.VR27H
    | "vr27l" -> Register.VR27L
    | "vr28h" -> Register.VR28H
    | "vr28l" -> Register.VR28L
    | "vr29h" -> Register.VR29H
    | "vr29l" -> Register.VR29L
    | "vr30h" -> Register.VR30H
    | "vr30l" -> Register.VR30L
    | "vr31h" -> Register.VR31H
    | "vr31l" -> Register.VR31L
    | _ -> Terminator.impossible ()

  /// Returns the register ID of a S390 register.
  [<CompiledName "ToRegID">]
  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue reg |> RegisterID.create

  /// Returns the string representation of a S390 register.
  [<CompiledName "ToString">]
  let toString reg =
    match reg with
    | Register.R0 -> "R0"
    | Register.R1 -> "R1"
    | Register.R2 -> "R2"
    | Register.R3 -> "R3"
    | Register.R4 -> "R4"
    | Register.R5 -> "R5"
    | Register.R6 -> "R6"
    | Register.R7 -> "R7"
    | Register.R8 -> "R8"
    | Register.R9 -> "R9"
    | Register.R10 -> "R10"
    | Register.R11 -> "R11"
    | Register.R12 -> "R12"
    | Register.R13 -> "R13"
    | Register.R14 -> "R14"
    | Register.R15 -> "R15"
    | Register.FPR0 -> "FPR0"
    | Register.FPR1 -> "FPR1"
    | Register.FPR2 -> "FPR2"
    | Register.FPR3 -> "FPR3"
    | Register.FPR4 -> "FPR4"
    | Register.FPR5 -> "FPR5"
    | Register.FPR6 -> "FPR6"
    | Register.FPR7 -> "FPR7"
    | Register.FPR8 -> "FPR8"
    | Register.FPR9 -> "FPR9"
    | Register.FPR10 -> "FPR10"
    | Register.FPR11 -> "FPR11"
    | Register.FPR12 -> "FPR12"
    | Register.FPR13 -> "FPR13"
    | Register.FPR14 -> "FPR14"
    | Register.FPR15 -> "FPR15"
    | Register.FPC -> "FPC"
    | Register.VR0 -> "VR0"
    | Register.VR1 -> "VR1"
    | Register.VR2 -> "VR2"
    | Register.VR3 -> "VR3"
    | Register.VR4 -> "VR4"
    | Register.VR5 -> "VR5"
    | Register.VR6 -> "VR6"
    | Register.VR7 -> "VR7"
    | Register.VR8 -> "VR8"
    | Register.VR9 -> "VR9"
    | Register.VR10 -> "VR10"
    | Register.VR11 -> "VR11"
    | Register.VR12 -> "VR12"
    | Register.VR13 -> "VR13"
    | Register.VR14 -> "VR14"
    | Register.VR15 -> "VR15"
    | Register.VR16 -> "VR16"
    | Register.VR17 -> "VR17"
    | Register.VR18 -> "VR18"
    | Register.VR19 -> "VR19"
    | Register.VR20 -> "VR20"
    | Register.VR21 -> "VR21"
    | Register.VR22 -> "VR22"
    | Register.VR23 -> "VR23"
    | Register.VR24 -> "VR24"
    | Register.VR25 -> "VR25"
    | Register.VR26 -> "VR26"
    | Register.VR27 -> "VR27"
    | Register.VR28 -> "VR28"
    | Register.VR29 -> "VR29"
    | Register.VR30 -> "VR30"
    | Register.VR31 -> "VR31"
    | Register.CR0 -> "CR0"
    | Register.CR1 -> "CR1"
    | Register.CR2 -> "CR2"
    | Register.CR3 -> "CR3"
    | Register.CR4 -> "CR4"
    | Register.CR5 -> "CR5"
    | Register.CR6 -> "CR6"
    | Register.CR7 -> "CR7"
    | Register.CR8 -> "CR8"
    | Register.CR9 -> "CR9"
    | Register.CR10 -> "CR10"
    | Register.CR11 -> "CR11"
    | Register.CR12 -> "CR12"
    | Register.CR13 -> "CR13"
    | Register.CR14 -> "CR14"
    | Register.CR15 -> "CR15"
    | Register.AR0 -> "AR0"
    | Register.AR1 -> "AR1"
    | Register.AR2 -> "AR2"
    | Register.AR3 -> "AR3"
    | Register.AR4 -> "AR4"
    | Register.AR5 -> "AR5"
    | Register.AR6 -> "AR6"
    | Register.AR7 -> "AR7"
    | Register.AR8 -> "AR8"
    | Register.AR9 -> "AR9"
    | Register.AR10 -> "AR10"
    | Register.AR11 -> "AR11"
    | Register.AR12 -> "AR12"
    | Register.AR13 -> "AR13"
    | Register.AR14 -> "AR14"
    | Register.AR15 -> "AR15"
    | Register.BEAR -> "BEAR"
    | Register.PSW -> "PSW"
    | Register.PC -> "PC"
    | Register.CC -> "CC"
    | Register.SVCCODE -> "SVCCODE"
    | Register.VR0L -> "VR0L"
    | Register.VR1L -> "VR1L"
    | Register.VR2L -> "VR2L"
    | Register.VR3L -> "VR3L"
    | Register.VR4L -> "VR4L"
    | Register.VR5L -> "VR5L"
    | Register.VR6L -> "VR6L"
    | Register.VR7L -> "VR7L"
    | Register.VR8L -> "VR8L"
    | Register.VR9L -> "VR9L"
    | Register.VR10L -> "VR10L"
    | Register.VR11L -> "VR11L"
    | Register.VR12L -> "VR12L"
    | Register.VR13L -> "VR13L"
    | Register.VR14L -> "VR14L"
    | Register.VR15L -> "VR15L"
    | Register.VR16H -> "VR16H"
    | Register.VR16L -> "VR16L"
    | Register.VR17H -> "VR17H"
    | Register.VR17L -> "VR17L"
    | Register.VR18H -> "VR18H"
    | Register.VR18L -> "VR18L"
    | Register.VR19H -> "VR19H"
    | Register.VR19L -> "VR19L"
    | Register.VR20H -> "VR20H"
    | Register.VR20L -> "VR20L"
    | Register.VR21H -> "VR21H"
    | Register.VR21L -> "VR21L"
    | Register.VR22H -> "VR22H"
    | Register.VR22L -> "VR22L"
    | Register.VR23H -> "VR23H"
    | Register.VR23L -> "VR23L"
    | Register.VR24H -> "VR24H"
    | Register.VR24L -> "VR24L"
    | Register.VR25H -> "VR25H"
    | Register.VR25L -> "VR25L"
    | Register.VR26H -> "VR26H"
    | Register.VR26L -> "VR26L"
    | Register.VR27H -> "VR27H"
    | Register.VR27L -> "VR27L"
    | Register.VR28H -> "VR28H"
    | Register.VR28L -> "VR28L"
    | Register.VR29H -> "VR29H"
    | Register.VR29L -> "VR29L"
    | Register.VR30H -> "VR30H"
    | Register.VR30L -> "VR30L"
    | Register.VR31H -> "VR31H"
    | Register.VR31L -> "VR31L"
    | _ -> Terminator.impossible ()