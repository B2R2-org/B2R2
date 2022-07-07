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
  /// Program Counter.
  | PC = 0x100
  /// Floating point control and status register.
  | FCSR = 0x101



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
    | R.X8 -> "s0/fp"
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