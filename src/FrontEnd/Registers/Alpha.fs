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

namespace B2R2.FrontEnd.Alpha

open B2R2

/// <namespacedoc>
///   <summary>
///   Contains types and functions for working with the Alpha instructions.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents registers for Alpha.<para/>
/// </summary>
type Register =
  /// General register 0.
  | R0 = 0x0
  /// General register 1.
  | R1 = 0x1
  /// General register 2.
  | R2 = 0x2
  /// General register 3.
  | R3 = 0x3
  /// General register 4.
  | R4 = 0x4
  /// General register 5.
  | R5 = 0x5
  /// General register 6.
  | R6 = 0x6
  /// General register 7.
  | R7 = 0x7
  /// General register 8.
  | R8 = 0x8
  /// General register 9.
  | R9 = 0x9
  /// General register 10.
  | R10 = 0xA
  /// General register 11.
  | R11 = 0xB
  /// General register 12.
  | R12 = 0xC
  /// General register 13.
  | R13 = 0xD
  /// General register 14.
  | R14 = 0xE
  /// General register 15.
  | R15 = 0xF
  /// General register 16.
  | R16 = 0x10
  /// General register 17.
  | R17 = 0x11
  /// General register 18.
  | R18 = 0x12
  /// General register 19.
  | R19 = 0x13
  /// General register 20.
  | R20 = 0x14
  /// General register 21.
  | R21 = 0x15
  /// General register 22.
  | R22 = 0x16
  /// General register 23.
  | R23 = 0x17
  /// General register 24.
  | R24 = 0x18
  /// General register 25.
  | R25 = 0x19
  /// General register 26.
  | R26 = 0x1A
  /// General register 27.
  | R27 = 0x1B
  /// General register 28.
  | R28 = 0x1C
  /// General register 29.
  | R29 = 0x1D
  /// General register 30.
  | R30 = 0x1E
  /// General register 31.
  | R31 = 0x1F
  /// Floating-point register 0.
  | F0 = 0x20
  /// Floating-point register 1.
  | F1 = 0x21
  /// Floating-point register 2.
  | F2 = 0x22
  /// Floating-point register 3.
  | F3 = 0x23
  /// Floating-point register 4.
  | F4 = 0x24
  /// Floating-point register 5.
  | F5 = 0x25
  /// Floating-point register 6.
  | F6 = 0x26
  /// Floating-point register 7.
  | F7 = 0x27
  /// Floating-point register 8.
  | F8 = 0x28
  /// Floating-point register 9.
  | F9 = 0x29
  /// Floating-point register 10.
  | F10 = 0x2A
  /// Floating-point register 11.
  | F11 = 0x2B
  /// Floating-point register 12.
  | F12 = 0x2C
  /// Floating-point register 13.
  | F13 = 0x2D
  /// Floating-point register 14.
  | F14 = 0x2E
  /// Floating-point register 15.
  | F15 = 0x2F
  /// Floating-point register 16.
  | F16 = 0x30
  /// Floating-point register 17.
  | F17 = 0x31
  /// Floating-point register 18.
  | F18 = 0x32
  /// Floating-point register 19.
  | F19 = 0x33
  /// Floating-point register 20.
  | F20 = 0x34
  /// Floating-point register 21.
  | F21 = 0x35
  /// Floating-point register 22.
  | F22 = 0x36
  /// Floating-point register 23.
  | F23 = 0x37
  /// Floating-point register 24.
  | F24 = 0x38
  /// Floating-point register 25.
  | F25 = 0x39
  /// Floating-point register 26.
  | F26 = 0x3A
  /// Floating-point register 27.
  | F27 = 0x3B
  /// Floating-point register 28.
  | F28 = 0x3C
  /// Floating-point register 29.
  | F29 = 0x3D
  /// Floating-point register 30.
  | F30 = 0x3E
  /// Floating-point register 31.
  | F31 = 0x3F
  /// Program counter.
  | PC = 0x40
  /// Floating-point control register.
  | FPCR = 0x41
  /// The process unique value, which is what the PALcode routines reading and
  /// writing it hand a program in place of a thread register of its own. Linux
  /// keeps the thread pointer here.
  | UNIQ = 0x42
  /// Pseudo register: the address a load-locked reserved, for a value-based
  /// exclusive-monitor model. See ExMonVal.
  | ExMonAddr = 0x43
  /// Pseudo register: the memory value at ExMonAddr when the load-locked ran,
  /// so a later store-conditional can tell whether anything wrote over it.
  | ExMonVal = 0x44

/// Provides functions to handle Alpha registers.
module Register =
  /// Returns the Alpha register from a register ID.
  [<CompiledName "OfRegID">]
  let inline ofRegID (rid: RegisterID): Register =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Returns the Alpha register from a string representation.
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
    | "pc" -> Register.PC
    | "fpcr" -> Register.FPCR
    | "uniq" -> Register.UNIQ
    | "exmonaddr" -> Register.ExMonAddr
    | "exmonval" -> Register.ExMonVal
    | _ -> Terminator.impossible ()

  /// Returns the register ID of an Alpha register.
  [<CompiledName "ToRegID">]
  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue reg |> RegisterID.create

  /// Returns the string representation of an Alpha register.
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
    | Register.PC -> "pc"
    | Register.FPCR -> "fpcr"
    | Register.UNIQ -> "uniq"
    | Register.ExMonAddr -> "exmonaddr"
    | Register.ExMonVal -> "exmonval"
    | _ -> Terminator.impossible ()

// vim: set tw=80 sts=2 sw=2:
