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

namespace B2R2.FrontEnd.MIPS

open B2R2

/// <summary>
/// Represents registers for MIPS32 and MIPS64.<para/>
/// </summary>
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
  /// Floating Point Control and Status Register.
  | FCSR = 0x105
  /// Floating Point Implementation Register.
  | FIR = 0x106

/// Provides functions to handle MIPS registers.
[<RequireQualifiedAccess>]
module Register =
  /// Returns the MIPS register from a register ID.
  [<CompiledName "OfRegID">]
  let inline ofRegID (rid: RegisterID): Register =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Returns the MIPS register from a string representation.
  [<CompiledName "OfString">]
  let ofString (str: string) wordSize =
    match str.ToLowerInvariant() with
    | "r0" -> Register.R0
    | "r1" | "at" -> Register.R1
    | "r2" | "v0" -> Register.R2
    | "r3" | "v1" -> Register.R3
    | "r4" | "a0" -> Register.R4
    | "r5" | "a1" -> Register.R5
    | "r6" | "a2" -> Register.R6
    | "r7" | "a3" -> Register.R7
    | "r8" | "a4" -> Register.R8
    | "r9" | "a5" -> Register.R9
    | "r10" | "a6" -> Register.R10
    | "r11" | "a7" -> Register.R11
    | "t0" -> if wordSize = WordSize.Bit32 then Register.R8 else Register.R12
    | "t1" -> if wordSize = WordSize.Bit32 then Register.R9 else Register.R13
    | "t2" -> if wordSize = WordSize.Bit32 then Register.R10 else Register.R14
    | "t3" -> if wordSize = WordSize.Bit32 then Register.R11 else Register.R15
    | "r12" | "t4" -> Register.R12
    | "r13" | "t5" -> Register.R13
    | "r14" | "t6" -> Register.R14
    | "r15" | "t7" -> Register.R15
    | "r16" | "s0" -> Register.R16
    | "r17" | "s1" -> Register.R17
    | "r18" | "s2" -> Register.R18
    | "r19" | "s3" -> Register.R19
    | "r20" | "s4" -> Register.R20
    | "r21" | "s5" -> Register.R21
    | "r22" | "s6" -> Register.R22
    | "r23" | "s7" -> Register.R23
    | "r24" | "t8" -> Register.R24
    | "r25" | "t9" -> Register.R25
    | "r26" | "k0" -> Register.R26
    | "r27" | "k1" -> Register.R27
    | "r28" | "gp" -> Register.R28
    | "r29" | "sp" -> Register.R29
    | "r30" | "fp" -> Register.R30
    | "r31" | "ra" -> Register.R31
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
    | "hi" -> Register.HI
    | "lo" -> Register.LO
    | "pc" -> Register.PC
    | "llbit" -> Register.LLBit
    | "fcsr" -> Register.FCSR
    | "fir" -> Register.FIR
    | _ -> Terminator.impossible ()

  /// Returns the register ID of a MIPS register.
  [<CompiledName "ToRegID">]
  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue(reg) |> RegisterID.create

  /// Returns the string representation of a MIPS register.
  [<CompiledName "ToString">]
  let toString reg wordSize =
    match wordSize with
    | WordSize.Bit32 ->
      match reg with
      | Register.R0  -> "r0"
      | Register.R1  -> "at"
      | Register.R2  -> "v0"
      | Register.R3  -> "v1"
      | Register.R4  -> "a0"
      | Register.R5  -> "a1"
      | Register.R6  -> "a2"
      | Register.R7  -> "a3"
      | Register.R8  -> "t0"
      | Register.R9  -> "t1"
      | Register.R10 -> "t2"
      | Register.R11 -> "t3"
      | Register.R12 -> "t4"
      | Register.R13 -> "t5"
      | Register.R14 -> "t6"
      | Register.R15 -> "t7"
      | Register.R16 -> "s0"
      | Register.R17 -> "s1"
      | Register.R18 -> "s2"
      | Register.R19 -> "s3"
      | Register.R20 -> "s4"
      | Register.R21 -> "s5"
      | Register.R22 -> "s6"
      | Register.R23 -> "s7"
      | Register.R24 -> "t8"
      | Register.R25 -> "t9"
      | Register.R26 -> "k0"
      | Register.R27 -> "k1"
      | Register.R28 -> "gp"
      | Register.R29 -> "sp"
      | Register.R30 -> "fp"
      | Register.R31 -> "ra"
      | Register.F0  -> "f0"
      | Register.F1  -> "f1"
      | Register.F2  -> "f2"
      | Register.F3  -> "f3"
      | Register.F4  -> "f4"
      | Register.F5  -> "f5"
      | Register.F6  -> "f6"
      | Register.F7  -> "f7"
      | Register.F8  -> "f8"
      | Register.F9  -> "f9"
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
      | Register.HI  -> "hi"
      | Register.LO  -> "lo"
      | Register.PC  -> "pc"
      | Register.LLBit -> "LLBit"
      | Register.FCSR -> "fcsr"
      | Register.FIR -> "fir"
      | _ -> Terminator.impossible ()
    | WordSize.Bit64 ->
      match reg with
      | Register.R0  -> "r0"
      | Register.R1  -> "at"
      | Register.R2  -> "v0"
      | Register.R3  -> "v1"
      | Register.R4  -> "a0"
      | Register.R5  -> "a1"
      | Register.R6  -> "a2"
      | Register.R7  -> "a3"
      | Register.R8  -> "a4"
      | Register.R9  -> "a5"
      | Register.R10 -> "a6"
      | Register.R11 -> "a7"
      | Register.R12 -> "t0"
      | Register.R13 -> "t1"
      | Register.R14 -> "t2"
      | Register.R15 -> "t3"
      | Register.R16 -> "s0"
      | Register.R17 -> "s1"
      | Register.R18 -> "s2"
      | Register.R19 -> "s3"
      | Register.R20 -> "s4"
      | Register.R21 -> "s5"
      | Register.R22 -> "s6"
      | Register.R23 -> "s7"
      | Register.R24 -> "t8"
      | Register.R25 -> "t9"
      | Register.R26 -> "k0"
      | Register.R27 -> "k1"
      | Register.R28 -> "gp"
      | Register.R29 -> "sp"
      | Register.R30 -> "s8"
      | Register.R31 -> "ra"
      | Register.F0  -> "f0"
      | Register.F1  -> "f1"
      | Register.F2  -> "f2"
      | Register.F3  -> "f3"
      | Register.F4  -> "f4"
      | Register.F5  -> "f5"
      | Register.F6  -> "f6"
      | Register.F7  -> "f7"
      | Register.F8  -> "f8"
      | Register.F9  -> "f9"
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
      | Register.HI  -> "hi"
      | Register.LO  -> "lo"
      | Register.PC  -> "pc"
      | Register.LLBit -> "LLBit"
      | Register.FCSR -> "fcsr"
      | Register.FIR -> "fir"
      | _ -> Terminator.impossible ()
    | _ -> Terminator.impossible ()
