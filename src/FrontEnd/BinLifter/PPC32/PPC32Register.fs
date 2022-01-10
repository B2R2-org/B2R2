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

namespace B2R2.FrontEnd.BinLifter.PPC32

open B2R2

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
  | CR0 = 0x40
  | CR1 = 0x41
  | CR2 = 0x42
  | CR3 = 0x43
  | CR4 = 0x44
  | CR5 = 0x45
  | CR6 = 0x46
  | CR7 = 0x47

/// Shortcut for Register type.
type internal R = Register
type internal F = Register
type internal CR = Register

/// This module exposes several useful functions to handle PPC32
/// registers.
[<RequireQualifiedAccess>]
module Register =
  let inline ofRegID (n: RegisterID): Register =
    int n |> LanguagePrimitives.EnumOfValue

  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  let ofString (str: string) =
    match str.ToLower () with
    | "r0" -> R.R0 (* FIXME: Add Registers *)
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
    | "f0" -> F.F0
    | "f1" -> F.F1
    | "f2" -> F.F2
    | "f3" -> F.F3
    | "f4" -> F.F4
    | "f5" -> F.F5
    | "f6" -> F.F6
    | "f7" -> F.F7
    | "f8" -> F.F8
    | "f9" -> F.F9
    | "f10" -> F.F10
    | "f11" -> F.F11
    | "f12" -> F.F12
    | "f13" -> F.F13
    | "f14" -> F.F14
    | "f15" -> F.F15
    | "f16" -> F.F16
    | "f17" -> F.F17
    | "f18" -> F.F18
    | "f19" -> F.F19
    | "f20" -> F.F20
    | "f21" -> F.F21
    | "f22" -> F.F22
    | "f23" -> F.F23
    | "f24" -> F.F24
    | "f25" -> F.F25
    | "f26" -> F.F26
    | "f27" -> F.F27
    | "f28" -> F.F28
    | "f29" -> F.F29
    | "f30" -> F.F30
    | "f31" -> F.F31
    | "cr0" -> CR.CR0
    | "cr1" -> CR.CR1
    | "cr2" -> CR.CR2
    | "cr3" -> CR.CR3
    | "cr4" -> CR.CR4
    | "cr5" -> CR.CR5
    | "cr6" -> CR.CR6
    | "cr7" -> CR.CR7
    | _ -> Utils.impossible ()

  let toString = function
    | R.R0 -> "r0" (* FIXME: Add Registers *)
    | R.R1 -> "r1"
    | R.R2 -> "r2"
    | R.R3 -> "r3"
    | R.R4 -> "r4"
    | R.R5 -> "r5"
    | R.R6 -> "r6"
    | R.R7 -> "r7"
    | R.R8 -> "r8"
    | R.R9 -> "r9"
    | R.R10 -> "r10"
    | R.R11 -> "r11"
    | R.R12 -> "r12"
    | R.R13 -> "r13"
    | R.R14 -> "r14"
    | R.R15 -> "r15"
    | R.R16 -> "r16"
    | R.R17 -> "r17"
    | R.R18 -> "r18"
    | R.R19 -> "r19"
    | R.R20 -> "r20"
    | R.R21 -> "r21"
    | R.R22 -> "r22"
    | R.R23 -> "r23"
    | R.R24 -> "r24"
    | R.R25 -> "r25"
    | R.R26 -> "r26"
    | R.R27 -> "r27"
    | R.R28 -> "r28"
    | R.R29 -> "r29"
    | R.R30 -> "r30"
    | R.R31 -> "r31"
    | F.F0 -> "f0"
    | F.F1 -> "f1"
    | F.F2 -> "f2"
    | F.F3 -> "f3"
    | F.F4 -> "f4"
    | F.F5 -> "f5"
    | F.F6 -> "f6"
    | F.F7 -> "f7"
    | F.F8 -> "f8"
    | F.F9 -> "f9"
    | F.F10 -> "f10"
    | F.F11 -> "f11"
    | F.F12 -> "f12"
    | F.F13 -> "f13"
    | F.F14 -> "f14"
    | F.F15 -> "f15"
    | F.F16 -> "f16"
    | F.F17 -> "f17"
    | F.F18 -> "f18"
    | F.F19 -> "f19"
    | F.F20 -> "f20"
    | F.F21 -> "f21"
    | F.F22 -> "f22"
    | F.F23 -> "f23"
    | F.F24 -> "f24"
    | F.F25 -> "f25"
    | F.F26 -> "f26"
    | F.F27 -> "f27"
    | F.F28 -> "f28"
    | F.F29 -> "f29"
    | F.F30 -> "f30"
    | F.F31 -> "f31"
    | CR.CR0 -> "cr0"
    | CR.CR1 -> "cr1"
    | CR.CR2 -> "cr2"
    | CR.CR3 -> "cr3"
    | CR.CR4 -> "cr4"
    | CR.CR5 -> "cr5"
    | CR.CR6 -> "cr6"
    | CR.CR7 -> "cr7"
    | _ -> Utils.impossible ()