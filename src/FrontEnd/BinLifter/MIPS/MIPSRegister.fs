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

namespace B2R2.FrontEnd.BinLifter.MIPS

open B2R2

/// MIPS Registers
/// https://en.wikibooks.org/wiki/MIPS_Assembly/Register_File
type Register =
  /// $zero or $r0 - Always zero
  | R0 = 0x0
  /// $at - Reservd for assembler.
  | R1 = 0x1
  /// $v0 - First and second return values, respectively.
  | R2 = 0x2
  /// $v1 - First and second return values, respectively.
  | R3 = 0x3
  /// $a0 - First four arguments to functions.
  | R4 = 0x4
  /// $a1 - First four arguments to functions.
  | R5 = 0x5
  /// $a2 - First four arguments to functions.
  | R6 = 0x6
  /// $a3 - First four arguments to functions.
  | R7 = 0x7
  /// $t0 - Temporary register.
  | R8 = 0x8
  /// $t1 - Temporary register.
  | R9 = 0x9
  /// $t2 - Temporary register.
  | R10 = 0xA
  /// $t3 - Temporary register.
  | R11 = 0xB
  /// $t4 - Temporary register.
  | R12 = 0xC
  /// $t5 - Temporary register.
  | R13 = 0xD
  /// $t6 - Temporary register.
  | R14 = 0xE
  /// $t7 - Temporary register.
  | R15 = 0xF
  /// $s0 - Saved register.
  | R16 = 0x10
  /// $s1 - Saved register.
  | R17 = 0x11
  /// $s2 - Saved register.
  | R18 = 0x12
  /// $s3 - Saved register.
  | R19 = 0x13
  /// $s4 - Saved register.
  | R20 = 0x14
  /// $s5 - Saved register.
  | R21 = 0x15
  /// $s6 - Saved register.
  | R22 = 0x16
  /// $s7 - Saved register.
  | R23 = 0x17
  /// $t8 - More temporary register.
  | R24 = 0x18
  /// $t9 - More temporary register.
  | R25 = 0x19
  /// $k0 - Reserved for kernel (operating system).
  | R26 = 0x1A
  /// $k1 - Reserved for kernel (operating system).
  | R27 = 0x1B
  /// $gp - Global pointer.
  | R28 = 0x1C
  /// $sp - Stack pointer.
  | R29 = 0x1D
  /// $fp - Frame pointer.
  | R30 = 0x1E
  /// $ra - Return address.
  | R31 = 0x1F
  /// Floating point Register.
  | F0 = 0x20
  /// Floating point Register.
  | F1 = 0x21
  /// Floating point Register.
  | F2 = 0x22
  /// Floating point Register.
  | F3 = 0x23
  /// Floating point Register.
  | F4 = 0x24
  /// Floating point Register.
  | F5 = 0x25
  /// Floating point Register.
  | F6 = 0x26
  /// Floating point Register.
  | F7 = 0x27
  /// Floating point Register.
  | F8 = 0x28
  /// Floating point Register.
  | F9 = 0x29
  /// Floating point Register.
  | F10 =0x2A
  /// Floating point Register.
  | F11 = 0x2B
  /// Floating point Register.
  | F12 = 0x2C
  /// Floating point Register.
  | F13 = 0x2D
  /// Floating point Register.
  | F14 = 0x2E
  /// Floating point Register.
  | F15 = 0x2F
  /// Floating point Register.
  | F16 = 0x30
  /// Floating point Register.
  | F17 = 0x31
  /// Floating point Register.
  | F18 = 0x32
  /// Floating point Register.
  | F19 = 0x33
  /// Floating point Register.
  | F20 = 0x34
  /// Floating point Register.
  | F21 = 0x35
  /// Floating point Register.
  | F22 = 0x36
  /// Floating point Register.
  | F23 = 0x37
  /// Floating point Register.
  | F24 = 0x38
  /// Floating point Register.
  | F25 = 0x39
  /// Floating point Register.
  | F26 = 0x3A
  /// Floating point Register.
  | F27 = 0x3B
  /// Floating point Register.
  | F28 = 0x3C
  /// Floating point Register.
  | F29 = 0x3D
  /// Floating point Register.
  | F30 = 0x3E
  /// Floating point Register.
  | F31 = 0x3F
  /// Accumulator High (Acc 63:32)
  | HI = 0x100
  /// Accumulator Low (Acc 31:0)
  | LO = 0x101
  /// Program Counter.
  | PC = 0x102
  /// Pseudo register for the next PC (nPC).
  | NPC = 0x103
  /// Pseudo register for LLBit. This is used to store the actual LLBit value
  /// from the CPU after an exception.
  | LLBit = 0x104

/// Shortcut for Register type.
type internal R = Register

/// This module exposes several useful functions to handle MIPS registers.
[<RequireQualifiedAccess>]
module Register =
  let inline ofRegID (n: RegisterID): Register =
    int n |> LanguagePrimitives.EnumOfValue

  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  let ofString (str: string) =
    match str.ToLowerInvariant () with
    | "r0" -> R.R0
    | "r1" -> R.R1
    | "r2" -> R.R2
    | "r3" -> R.R3
    | "r4" -> R.R4
    | "r5" -> R.R5
    | "r6" -> R.R6
    | "r7" -> R.R7
    | "r8" -> R.R8
    | "r9" -> R.R9
    | "r10" -> R.R10
    | "r11" -> R.R11
    | "r12" -> R.R12
    | "r13" -> R.R13
    | "r14" -> R.R14
    | "r15" -> R.R15
    | "r16" -> R.R16
    | "r17" -> R.R17
    | "r18" -> R.R18
    | "r19" -> R.R19
    | "r20" -> R.R20
    | "r21" -> R.R21
    | "r22" -> R.R22
    | "r23" -> R.R23
    | "r24" -> R.R24
    | "r25" -> R.R25
    | "r26" -> R.R26
    | "r27" -> R.R27
    | "r28" -> R.R28
    | "r29" -> R.R29
    | "r30" -> R.R30
    | "r31" -> R.R31
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
    | "hi" -> R.HI
    | "lo" -> R.LO
    | "pc" -> R.PC
    | "llbit" -> R.LLBit
    | _ -> Utils.impossible ()

  let toString32 = function
    | R.R0  -> "r0"
    | R.R1  -> "at"
    | R.R2  -> "v0"
    | R.R3  -> "v1"
    | R.R4  -> "a0"
    | R.R5  -> "a1"
    | R.R6  -> "a2"
    | R.R7  -> "a3"
    | R.R8  -> "t0"
    | R.R9  -> "t1"
    | R.R10 -> "t2"
    | R.R11 -> "t3"
    | R.R12 -> "t4"
    | R.R13 -> "t5"
    | R.R14 -> "t6"
    | R.R15 -> "t7"
    | R.R16 -> "s0"
    | R.R17 -> "s1"
    | R.R18 -> "s2"
    | R.R19 -> "s3"
    | R.R20 -> "s4"
    | R.R21 -> "s5"
    | R.R22 -> "s6"
    | R.R23 -> "s7"
    | R.R24 -> "t8"
    | R.R25 -> "t9"
    | R.R26 -> "k0"
    | R.R27 -> "k1"
    | R.R28 -> "gp"
    | R.R29 -> "sp"
    | R.R30 -> "fp"
    | R.R31 -> "ra"
    | R.F0  -> "f0"
    | R.F1  -> "f1"
    | R.F2  -> "f2"
    | R.F3  -> "f3"
    | R.F4  -> "f4"
    | R.F5  -> "f5"
    | R.F6  -> "f6"
    | R.F7  -> "f7"
    | R.F8  -> "f8"
    | R.F9  -> "f9"
    | R.F10 -> "f10"
    | R.F11 -> "f11"
    | R.F12 -> "f12"
    | R.F13 -> "f13"
    | R.F14 -> "f14"
    | R.F15 -> "f15"
    | R.F16 -> "f16"
    | R.F17 -> "f17"
    | R.F18 -> "f18"
    | R.F19 -> "f19"
    | R.F20 -> "f20"
    | R.F21 -> "f21"
    | R.F22 -> "f22"
    | R.F23 -> "f23"
    | R.F24 -> "f24"
    | R.F25 -> "f25"
    | R.F26 -> "f26"
    | R.F27 -> "f27"
    | R.F28 -> "f28"
    | R.F29 -> "f29"
    | R.F30 -> "f30"
    | R.F31 -> "f31"
    | R.HI  -> "hi"
    | R.LO  -> "lo"
    | R.PC  -> "pc"
    | R.LLBit -> "LLBit"
    | _ -> Utils.impossible ()

  let toString64 = function
    | R.R0  -> "r0"
    | R.R1  -> "at"
    | R.R2  -> "v0"
    | R.R3  -> "v1"
    | R.R4  -> "a0"
    | R.R5  -> "a1"
    | R.R6  -> "a2"
    | R.R7  -> "a3"
    | R.R8  -> "a4"
    | R.R9  -> "a5"
    | R.R10 -> "a6"
    | R.R11 -> "a7"
    | R.R12 -> "t0"
    | R.R13 -> "t1"
    | R.R14 -> "t2"
    | R.R15 -> "t3"
    | R.R16 -> "s0"
    | R.R17 -> "s1"
    | R.R18 -> "s2"
    | R.R19 -> "s3"
    | R.R20 -> "s4"
    | R.R21 -> "s5"
    | R.R22 -> "s6"
    | R.R23 -> "s7"
    | R.R24 -> "t8"
    | R.R25 -> "t9"
    | R.R26 -> "k0"
    | R.R27 -> "k1"
    | R.R28 -> "gp"
    | R.R29 -> "sp"
    | R.R30 -> "s8"
    | R.R31 -> "ra"
    | R.F0  -> "f0"
    | R.F1  -> "f1"
    | R.F2  -> "f2"
    | R.F3  -> "f3"
    | R.F4  -> "f4"
    | R.F5  -> "f5"
    | R.F6  -> "f6"
    | R.F7  -> "f7"
    | R.F8  -> "f8"
    | R.F9  -> "f9"
    | R.F10 -> "f10"
    | R.F11 -> "f11"
    | R.F12 -> "f12"
    | R.F13 -> "f13"
    | R.F14 -> "f14"
    | R.F15 -> "f15"
    | R.F16 -> "f16"
    | R.F17 -> "f17"
    | R.F18 -> "f18"
    | R.F19 -> "f19"
    | R.F20 -> "f20"
    | R.F21 -> "f21"
    | R.F22 -> "f22"
    | R.F23 -> "f23"
    | R.F24 -> "f24"
    | R.F25 -> "f25"
    | R.F26 -> "f26"
    | R.F27 -> "f27"
    | R.F28 -> "f28"
    | R.F29 -> "f29"
    | R.F30 -> "f30"
    | R.F31 -> "f31"
    | R.HI  -> "hi"
    | R.LO  -> "lo"
    | R.PC  -> "pc"
    | R.LLBit -> "LLBit"
    | _ -> Utils.impossible ()
