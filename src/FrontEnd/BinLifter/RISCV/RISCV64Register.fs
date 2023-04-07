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

namespace B2R2.FrontEnd.BinLifter.RISCV

open B2R2

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
  | CSR0768 = 0x40
  | CSR0769 = 0x41
  | CSR0770 = 0x42
  | CSR0771 = 0x43
  | CSR0772 = 0x44
  | CSR0773 = 0x45
  | CSR0784 = 0x46
  | CSR0832 = 0x47
  | CSR0833 = 0x48
  | CSR0834 = 0x49
  | CSR0835 = 0x4A
  | CSR0836 = 0x4B
  | CSR0842 = 0x4C
  | CSR0843 = 0x4D
  | CSR3857 = 0x4E
  | CSR3858 = 0x4F
  | CSR3859 = 0x50
  | CSR3860 = 0x51
  | CSR0928 = 0x52
  | CSR0930 = 0x53
  | CSR0932 = 0x54
  | CSR0934 = 0x55
  | CSR0936 = 0x56
  | CSR0938 = 0x57
  | CSR0940 = 0x58
  | CSR0942 = 0x59
  | CSR0944 = 0x5A
  | CSR0945 = 0x5B
  | CSR0946 = 0x5C
  | CSR0947 = 0x5D
  | CSR0948 = 0x5E
  | CSR0949 = 0x5F
  | CSR0950 = 0x60
  | CSR0951 = 0x61
  | CSR0952 = 0x62
  | CSR0953 = 0x63
  | CSR0954 = 0x64
  | CSR0955 = 0x65
  | CSR0956 = 0x66
  | CSR0957 = 0x67
  | CSR0958 = 0x68
  | CSR0959 = 0x69
  | CSR0960 = 0x6A
  | CSR0961 = 0x6B
  | CSR0962 = 0x6C
  | CSR0963 = 0x6D
  | CSR0964 = 0x6E
  | CSR0965 = 0x6F
  | CSR0966 = 0x70
  | CSR0967 = 0x71
  | CSR0968 = 0x72
  | CSR0969 = 0x73
  | CSR0970 = 0x74
  | CSR0971 = 0x75
  | CSR0972 = 0x76
  | CSR0973 = 0x77
  | CSR0974 = 0x78
  | CSR0975 = 0x79
  | CSR0976 = 0x7A
  | CSR0977 = 0x7B
  | CSR0978 = 0x7C
  | CSR0979 = 0x7D
  | CSR0980 = 0x7E
  | CSR0981 = 0x7F
  | CSR0982 = 0x80
  | CSR0983 = 0x81
  | CSR0984 = 0x82
  | CSR0985 = 0x83
  | CSR0986 = 0x84
  | CSR0987 = 0x85
  | CSR0988 = 0x86
  | CSR0989 = 0x87
  | CSR0990 = 0x88
  | CSR0991 = 0x89
  | CSR0992 = 0x8A
  | CSR0993 = 0x8B
  | CSR0994 = 0x8C
  | CSR0995 = 0x8D
  | CSR0996 = 0x8E
  | CSR0997 = 0x8F
  | CSR0998 = 0x90
  | CSR0999 = 0x91
  | CSR1000 = 0x92
  | CSR1001 = 0x93
  | CSR1002 = 0x94
  | CSR1003 = 0x95
  | CSR1004 = 0x96
  | CSR1005 = 0x97
  | CSR1006 = 0x98
  | CSR1007 = 0x99
  | CSR2816 = 0x9A
  | CSR2818 = 0x9B
  | CSR2819 = 0x9C
  | CSR2820 = 0x9D
  | CSR2821 = 0x9E
  | CSR2822 = 0x9F
  | CSR2823 = 0x100
  | CSR2824 = 0x101
  | CSR2825 = 0x102
  | CSR2826 = 0x103
  | CSR2827 = 0x104
  | CSR2828 = 0x105
  | CSR2829 = 0x106
  | CSR2830 = 0x107
  | CSR2831 = 0x108
  | CSR2832 = 0x109
  | CSR2833 = 0x10A
  | CSR2834 = 0x10B
  | CSR2835 = 0x10C
  | CSR2836 = 0x10D
  | CSR2837 = 0x10E
  | CSR2838 = 0x10F
  | CSR2839 = 0x110
  | CSR2840 = 0x111
  | CSR2841 = 0x112
  | CSR2842 = 0x113
  | CSR2843 = 0x114
  | CSR2844 = 0x115
  | CSR2845 = 0x116
  | CSR2846 = 0x117
  | CSR2847 = 0x118
  | CSR0800 = 0x119
  | CSR0803 = 0x11A
  | CSR0804 = 0x11B
  | CSR0805 = 0x11C
  | CSR0806 = 0x11D
  | CSR0807 = 0x11E
  | CSR0808 = 0x11F
  | CSR0809 = 0x120
  | CSR0810 = 0x121
  | CSR0811 = 0x122
  | CSR0812 = 0x123
  | CSR0813 = 0x124
  | CSR0814 = 0x125
  | CSR0815 = 0x126
  | CSR0816 = 0x127
  | CSR0817 = 0x128
  | CSR0818 = 0x129
  | CSR0819 = 0x12A
  | CSR0820 = 0x12B
  | CSR0821 = 0x12C
  | CSR0822 = 0x12D
  | CSR0823 = 0x12E
  | CSR0824 = 0x12F
  | CSR0825 = 0x130
  | CSR0826 = 0x131
  | CSR0827 = 0x132
  | CSR0828 = 0x133
  | CSR0829 = 0x134
  | CSR0830 = 0x135
  | CSR0831 = 0x136
  | CSR1952 = 0x137
  | CSR1953 = 0x138
  | CSR1954 = 0x139
  | CSR1955 = 0x13A
  | CSR1968 = 0x13B
  | CSR1969 = 0x13C
  | CSR1970 = 0x13D
  | CSR1971 = 0x13E
  /// Program Counter.
  | PC = 0x13F
  /// Floating point control and status register.
  | FCSR = 0x140



/// Shortcut for Register type.
type internal R = Register

/// This module exposes several useful functions to handle RISCV64
/// registers.
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
    | "x31" -> R.X31
    | "f0" -> R.F0
    | "f1" -> R.F1
    | "f2" -> R.F2
    | "f3" -> R.F3
    | "f4" -> R.F4
    | "f5" -> R.F5
    | "f6" -> R.F6
    | "f7" -> R.F7
    | "f8" -> R.F8
    | "f9" -> R.F9
    | "f10" -> R.F10
    | "f11" -> R.F11
    | "f12" -> R.F12
    | "f13" -> R.F13
    | "f14" -> R.F14
    | "f15" -> R.F15
    | "f16" -> R.F16
    | "f17" -> R.F17
    | "f18" -> R.F18
    | "f19" -> R.F19
    | "f20" -> R.F20
    | "f21" -> R.F21
    | "f22" -> R.F22
    | "f23" -> R.F23
    | "f24" -> R.F24
    | "f25" -> R.F25
    | "f26" -> R.F26
    | "f27" -> R.F27
    | "f28" -> R.F28
    | "f29" -> R.F29
    | "f30" -> R.F30
    | "f31" -> R.F31
    | "pc" -> R.PC
    | "fcsr" -> R.FCSR
    | _ -> Utils.impossible ()

  let toString = function
    | R.X0 -> "zero"
    | R.X1 -> "ra"
    | R.X2 -> "sp"
    | R.X3 -> "gp"
    | R.X4 -> "tp"
    | R.X5 -> "t0"
    | R.X6 -> "t1"
    | R.X7 -> "t2"
    | R.X8 -> "s0"
    | R.X9 -> "s1"
    | R.X10 -> "a0"
    | R.X11 -> "a1"
    | R.X12 -> "a2"
    | R.X13 -> "a3"
    | R.X14 -> "a4"
    | R.X15 -> "a5"
    | R.X16 -> "a6"
    | R.X17 -> "a7"
    | R.X18 -> "s2"
    | R.X19 -> "s3"
    | R.X20 -> "s4"
    | R.X21 -> "s5"
    | R.X22 -> "s6"
    | R.X23 -> "s7"
    | R.X24 -> "s8"
    | R.X25 -> "s9"
    | R.X26 -> "s10"
    | R.X27 -> "s11"
    | R.X28 -> "t3"
    | R.X29 -> "t4"
    | R.X30 -> "t5"
    | R.X31 -> "t6"
    | R.F0 -> "ft0"
    | R.F1 -> "ft1"
    | R.F2 -> "ft2"
    | R.F3 -> "ft3"
    | R.F4 -> "ft4"
    | R.F5 -> "ft5"
    | R.F6 -> "ft6"
    | R.F7 -> "ft7"
    | R.F8 -> "fs0"
    | R.F9 -> "fs1"
    | R.F10 -> "fa0"
    | R.F11 -> "fa1"
    | R.F12 -> "fa2"
    | R.F13 -> "fa3"
    | R.F14 -> "fa4"
    | R.F15 -> "fa5"
    | R.F16 -> "fa6"
    | R.F17 -> "fa7"
    | R.F18 -> "fs2"
    | R.F19 -> "fs3"
    | R.F20 -> "fs4"
    | R.F21 -> "fs5"
    | R.F22 -> "fs6"
    | R.F23 -> "fs7"
    | R.F24 -> "fs8"
    | R.F25 -> "fs9"
    | R.F26 -> "fs10"
    | R.F27 -> "fs11"
    | R.F28 -> "ft8"
    | R.F29 -> "ft9"
    | R.F30 -> "ft10"
    | R.F31 -> "ft11"
    | _ -> Utils.impossible ()

  let toRegType wordSize = function
    | R.PC | R.X0 | R.X1 | R.X2 | R.X3 | R.X4 | R.X5 | R.X6 | R.X7 | R.X8
    | R.X9 | R.X10 | R.X11 | R.X12 | R.X13 | R.X14 | R.X15 | R.X16 | R.X17
    | R.X18 | R.X19 | R.X20 | R.X21 | R.X22 | R.X23 | R.X24 | R.X25 | R.X26
    | R.X27 | R.X28 | R.X29 | R.X30 | R.X31 -> WordSize.toRegType wordSize
    | R.F0 | R.F1 | R.F2 | R.F3 | R.F4 | R.F5 | R.F6 | R.F7 | R.F8 | R.F9
    | R.F10 | R.F11 | R.F12 | R.F13 | R.F14 | R.F15 | R.F16 | R.F17 | R.F18
    | R.F19 | R.F20 | R.F21 | R.F22 | R.F23 | R.F24 | R.F25 | R.F26 | R.F27
    | R.F28 | R.F29 | R.F30 | R.F31 -> 64<rt>
    | R.FCSR -> 32<rt>
    | _ -> Utils.impossible ()