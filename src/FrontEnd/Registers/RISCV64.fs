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

namespace B2R2.FrontEnd.RISCV64

open B2R2

/// <summary>
/// Registers for RISC-V.<para/>
/// </summary>
type Register =
  /// zero - Hard-wired zero.
  | X0 = 0x0
  /// ra - Return address.
  | X1 = 0x1
  /// sp - Stack pointer.
  | X2 = 0x2
  /// gp - Global pointer.
  | X3 = 0x3
  /// tp - Thread pointer.
  | X4 = 0x4
  /// t0 - Temporary/alternate link register.
  | X5 = 0x5
  /// t1 - Temporary register.
  | X6 = 0x6
  /// t2 - Temporary register.
  | X7 = 0x7
  /// s0 or fp - Saved register/frame pointer.
  | X8 = 0x8
  /// s1 - Saved register.
  | X9 = 0x9
  /// a0 - Function argument/return value.
  | X10 = 0xA
  /// a1 - Function argument/return value.
  | X11 = 0xB
  /// a2 - Function argument.
  | X12 = 0xC
  /// a3 - Function argument.
  | X13 = 0xD
  /// a4 - Function argument.
  | X14 = 0xE
  /// a5 - Function argument.
  | X15 = 0xF
  /// a6 - Function argument.
  | X16 = 0x10
  /// a7 - Function argument.
  | X17 = 0x11
  /// s2 - Saved register.
  | X18 = 0x12
  /// s3 - Saved register.
  | X19 = 0x13
  /// s4 - Saved register.
  | X20 = 0x14
  /// s5 - Saved register.
  | X21 = 0x15
  /// s6 - Saved register.
  | X22 = 0x16
  /// s7 - Saved register.
  | X23 = 0x17
  /// s8 - Saved register.
  | X24 = 0x18
  /// s9 - Saved register.
  | X25 = 0x19
  /// s10 - Saved register.
  | X26 = 0x1A
  /// s11 - Saved registers
  | X27 = 0x1B
  /// t3 - Temporary register.
  | X28 = 0x1C
  /// t4 - Temporary register.
  | X29 = 0x1D
  /// t5 - Temporary register.
  | X30 = 0x1E
  /// t6 - Temporary register.
  | X31 = 0x1F
  /// ft0 - FP temporary register.
  | F0 = 0x20
  /// ft1 - FP temporary register.
  | F1 = 0x21
  /// ft2 - FP temporary register.
  | F2 = 0x22
  /// ft3 - FP temporary register.
  | F3 = 0x23
  /// ft4 - FP temporary register.
  | F4 = 0x24
  /// ft5 - FP temporary register.
  | F5 = 0x25
  /// ft6 - FP temporary register.
  | F6 = 0x26
  /// ft7 - FP temporary register.
  | F7 = 0x27
  /// fs0 - FP saved register.
  | F8 = 0x28
  /// fs1 - FP saved register.
  | F9 = 0x29
  /// fa0 - FP argument/return value.
  | F10 = 0x2A
  /// fa1 - FP argument/return value.
  | F11 = 0x2B
  /// fa2 - FP argument.
  | F12 = 0x2C
  /// fa3 - FP argument.
  | F13 = 0x2D
  /// fa4 - FP argument.
  | F14 = 0x2E
  /// fa5 - FP argument.
  | F15 = 0x2F
  /// fa6 - FP argument.
  | F16 = 0x30
  /// fa7 - FP argument.
  | F17 = 0x31
  /// fs2 - FP saved register.
  | F18 = 0x32
  /// fs3 - FP saved register.
  | F19 = 0x33
  /// fs4 - FP saved register.
  | F20 = 0x34
  /// fs5 - FP saved register.
  | F21 = 0x35
  /// fs6 - FP saved register.
  | F22 = 0x36
  /// fs7 - FP saved register.
  | F23 = 0x37
  /// fs8 - FP saved register.
  | F24 = 0x38
  /// fs9 - FP saved register.
  | F25 = 0x39
  /// fs10 - FP saved register.
  | F26 = 0x3A
  /// fs11 - FP saved register.
  | F27 = 0x3B
  /// ft8 - FP temporary register.
  | F28 = 0x3C
  /// ft9 - FP temporary register.
  | F29 = 0x3D
  /// ft10 - FP temporary register.
  | F30 = 0x3E
  /// ft11 - FP temporary register.
  | F31 = 0x3F
  /// Program Counter.
  | PC = 0x40
  /// Floating point control and status register.
  | FCSR = 0x41
  /// Floating-Point Accrued Exceptions.
  | FFLAGS = 0x42
  | CSR0768 = 0x43
  | CSR0769 = 0x44
  | CSR0770 = 0x45
  | CSR0771 = 0x46
  | CSR0772 = 0x47
  | CSR0773 = 0x48
  | CSR0784 = 0x49
  | CSR0832 = 0x4A
  | CSR0833 = 0x4B
  | CSR0834 = 0x4C
  | CSR0835 = 0x4D
  | CSR0836 = 0x4E
  | CSR0842 = 0x4F
  | CSR0843 = 0x50
  | CSR3857 = 0x51
  | CSR3858 = 0x52
  | CSR3859 = 0x53
  | CSR3860 = 0x54
  | CSR0928 = 0x55
  | CSR0930 = 0x56
  | CSR0932 = 0x57
  | CSR0934 = 0x58
  | CSR0936 = 0x59
  | CSR0938 = 0x5A
  | CSR0940 = 0x5B
  | CSR0942 = 0x5C
  | CSR0944 = 0x5D
  | CSR0945 = 0x5E
  | CSR0946 = 0x5F
  | CSR0947 = 0x60
  | CSR0948 = 0x61
  | CSR0949 = 0x62
  | CSR0950 = 0x63
  | CSR0951 = 0x64
  | CSR0952 = 0x65
  | CSR0953 = 0x66
  | CSR0954 = 0x67
  | CSR0955 = 0x68
  | CSR0956 = 0x69
  | CSR0957 = 0x6A
  | CSR0958 = 0x6B
  | CSR0959 = 0x6C
  | CSR0960 = 0x6D
  | CSR0961 = 0x6E
  | CSR0962 = 0x6F
  | CSR0963 = 0x70
  | CSR0964 = 0x71
  | CSR0965 = 0x72
  | CSR0966 = 0x73
  | CSR0967 = 0x74
  | CSR0968 = 0x75
  | CSR0969 = 0x76
  | CSR0970 = 0x77
  | CSR0971 = 0x78
  | CSR0972 = 0x79
  | CSR0973 = 0x7A
  | CSR0974 = 0x7B
  | CSR0975 = 0x7C
  | CSR0976 = 0x7D
  | CSR0977 = 0x7E
  | CSR0978 = 0x7F
  | CSR0979 = 0x80
  | CSR0980 = 0x81
  | CSR0981 = 0x82
  | CSR0982 = 0x83
  | CSR0983 = 0x84
  | CSR0984 = 0x85
  | CSR0985 = 0x86
  | CSR0986 = 0x87
  | CSR0987 = 0x88
  | CSR0988 = 0x89
  | CSR0989 = 0x8A
  | CSR0990 = 0x8B
  | CSR0991 = 0x8C
  | CSR0992 = 0x8D
  | CSR0993 = 0x8E
  | CSR0994 = 0x8F
  | CSR0995 = 0x90
  | CSR0996 = 0x91
  | CSR0997 = 0x92
  | CSR0998 = 0x93
  | CSR0999 = 0x94
  | CSR1000 = 0x95
  | CSR1001 = 0x96
  | CSR1002 = 0x97
  | CSR1003 = 0x98
  | CSR1004 = 0x99
  | CSR1005 = 0x9A
  | CSR1006 = 0x9B
  | CSR1007 = 0x9C
  | CSR2816 = 0x9D
  | CSR2818 = 0x9E
  | CSR2819 = 0x9F
  | CSR2820 = 0xA0
  | CSR2821 = 0xA1
  | CSR2822 = 0xA2
  | CSR2823 = 0x103
  | CSR2824 = 0x104
  | CSR2825 = 0x105
  | CSR2826 = 0x106
  | CSR2827 = 0x107
  | CSR2828 = 0x108
  | CSR2829 = 0x109
  | CSR2830 = 0x10A
  | CSR2831 = 0x10B
  | CSR2832 = 0x10C
  | CSR2833 = 0x10D
  | CSR2834 = 0x10E
  | CSR2835 = 0x10F
  | CSR2836 = 0x110
  | CSR2837 = 0x111
  | CSR2838 = 0x112
  | CSR2839 = 0x113
  | CSR2840 = 0x114
  | CSR2841 = 0x115
  | CSR2842 = 0x116
  | CSR2843 = 0x117
  | CSR2844 = 0x118
  | CSR2845 = 0x119
  | CSR2846 = 0x11A
  | CSR2847 = 0x11B
  | CSR0800 = 0x11C
  | CSR0803 = 0x11D
  | CSR0804 = 0x11E
  | CSR0805 = 0x11F
  | CSR0806 = 0x120
  | CSR0807 = 0x121
  | CSR0808 = 0x122
  | CSR0809 = 0x123
  | CSR0810 = 0x124
  | CSR0811 = 0x125
  | CSR0812 = 0x126
  | CSR0813 = 0x127
  | CSR0814 = 0x128
  | CSR0815 = 0x129
  | CSR0816 = 0x12A
  | CSR0817 = 0x12B
  | CSR0818 = 0x12C
  | CSR0819 = 0x12D
  | CSR0820 = 0x12E
  | CSR0821 = 0x12F
  | CSR0822 = 0x130
  | CSR0823 = 0x131
  | CSR0824 = 0x132
  | CSR0825 = 0x133
  | CSR0826 = 0x134
  | CSR0827 = 0x135
  | CSR0828 = 0x136
  | CSR0829 = 0x137
  | CSR0830 = 0x138
  | CSR0831 = 0x139
  | CSR1952 = 0x13A
  | CSR1953 = 0x13B
  | CSR1954 = 0x13C
  | CSR1955 = 0x13D
  | CSR1968 = 0x13E
  | CSR1969 = 0x13F
  | CSR1970 = 0x140
  | CSR1971 = 0x141
  | CSR3787 = 0x142
  | CSR2617 = 0x143
  | CSR3114 = 0x144
  | CSR2145 = 0X145
  | CSR2945 = 0x146
  /// Floating-Point Dynamic Rounding Mode.
  | FRM = 0x147
  /// Pseudo register for reservation check and follows the same format as ARM.
  | RC = 0x148

/// Helper module for RISC-V registers.
module Register =
  /// Get the RISC-V register from a register ID.
  [<CompiledName "OfRegID">]
  let inline ofRegID (rid: RegisterID): Register =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Get the RISC-V register from a string representation.
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant () with
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
    | "x31" -> Register.X31
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
    | "pc" -> Register.PC
    | "fcsr" -> Register.FCSR
    | "fflags" -> Register.FFLAGS
    | "frm" -> Register.FRM
    | "rc" -> Register.RC
    | _ -> Utils.impossible ()

  /// Get the register ID of a RISC-V register.
  [<CompiledName "ToRegID">]
  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  /// Get the string representation of a RISC-V register.
  [<CompiledName "ToString">]
  let toString reg =
    match reg with
    | Register.X0 -> "zero"
    | Register.X1 -> "ra"
    | Register.X2 -> "sp"
    | Register.X3 -> "gp"
    | Register.X4 -> "tp"
    | Register.X5 -> "t0"
    | Register.X6 -> "t1"
    | Register.X7 -> "t2"
    | Register.X8 -> "s0"
    | Register.X9 -> "s1"
    | Register.X10 -> "a0"
    | Register.X11 -> "a1"
    | Register.X12 -> "a2"
    | Register.X13 -> "a3"
    | Register.X14 -> "a4"
    | Register.X15 -> "a5"
    | Register.X16 -> "a6"
    | Register.X17 -> "a7"
    | Register.X18 -> "s2"
    | Register.X19 -> "s3"
    | Register.X20 -> "s4"
    | Register.X21 -> "s5"
    | Register.X22 -> "s6"
    | Register.X23 -> "s7"
    | Register.X24 -> "s8"
    | Register.X25 -> "s9"
    | Register.X26 -> "s10"
    | Register.X27 -> "s11"
    | Register.X28 -> "t3"
    | Register.X29 -> "t4"
    | Register.X30 -> "t5"
    | Register.X31 -> "t6"
    | Register.F0 -> "ft0"
    | Register.F1 -> "ft1"
    | Register.F2 -> "ft2"
    | Register.F3 -> "ft3"
    | Register.F4 -> "ft4"
    | Register.F5 -> "ft5"
    | Register.F6 -> "ft6"
    | Register.F7 -> "ft7"
    | Register.F8 -> "fs0"
    | Register.F9 -> "fs1"
    | Register.F10 -> "fa0"
    | Register.F11 -> "fa1"
    | Register.F12 -> "fa2"
    | Register.F13 -> "fa3"
    | Register.F14 -> "fa4"
    | Register.F15 -> "fa5"
    | Register.F16 -> "fa6"
    | Register.F17 -> "fa7"
    | Register.F18 -> "fs2"
    | Register.F19 -> "fs3"
    | Register.F20 -> "fs4"
    | Register.F21 -> "fs5"
    | Register.F22 -> "fs6"
    | Register.F23 -> "fs7"
    | Register.F24 -> "fs8"
    | Register.F25 -> "fs9"
    | Register.F26 -> "fs10"
    | Register.F27 -> "fs11"
    | Register.F28 -> "ft8"
    | Register.F29 -> "ft9"
    | Register.F30 -> "ft10"
    | Register.F31 -> "ft11"
    | Register.FCSR -> "fcsr"
    | Register.FFLAGS -> "fflags"
    | Register.FRM -> "frm"
    | Register.RC -> "rc"
    | _ -> Utils.impossible ()
