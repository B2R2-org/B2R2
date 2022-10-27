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
  | GPR0 = 0x0
  | GPR1 = 0x1
  | GPR2 = 0x2
  | GPR3 = 0x3
  | GPR4 = 0x4
  | GPR5 = 0x5
  | GPR6 = 0x6
  | GPR7 = 0x7
  | GPR8 = 0x8
  | GPR9 = 0x9
  | GPR10 = 0xA
  | GPR11 = 0xB
  | GPR12 = 0xC
  | GPR13 = 0xD
  | GPR14 = 0xE
  | GPR15 = 0xF
  | GPR16 = 0x10
  | GPR17 = 0x11
  | GPR18 = 0x12
  | GPR19 = 0x13
  | GPR20 = 0x14
  | GPR21 = 0x15
  | GPR22 = 0x16
  | GPR23 = 0x17
  | GPR24 = 0x18
  | GPR25 = 0x19
  | GPR26 = 0x1A
  | GPR27 = 0x1B
  | GPR28 = 0x1C
  | GPR29 = 0x1D
  | GPR30 = 0x1E
  | GPR31 = 0x1F
  | FPR0 = 0x20
  | FPR1 = 0x21
  | FPR2 = 0x22
  | FPR3 = 0x23
  | FPR4 = 0x24
  | FPR5 = 0x25
  | FPR6 = 0x26
  | FPR7 = 0x27
  | FPR8 = 0x28
  | FPR9 = 0x29
  | FPR10 = 0x2A
  | FPR11 = 0x2B
  | FPR12 = 0x2C
  | FPR13 = 0x2D
  | FPR14 = 0x2E
  | FPR15 = 0x2F
  | FPR16 = 0x30
  | FPR17 = 0x31
  | FPR18 = 0x32
  | FPR19 = 0x33
  | FPR20 = 0x34
  | FPR21 = 0x35
  | FPR22 = 0x36
  | FPR23 = 0x37
  | FPR24 = 0x38
  | FPR25 = 0x39
  | FPR26 = 0x3A
  | FPR27 = 0x3B
  | FPR28 = 0x3C
  | FPR29 = 0x3D
  | FPR30 = 0x3E
  | FPR31 = 0x3F
  | CR0 = 0x40
  | CR1 = 0x41
  | CR2 = 0x42
  | CR3 = 0x43
  | CR4 = 0x44
  | CR5 = 0x45
  | CR6 = 0x46
  | CR7 = 0x47
  /// XER Register.
  | XER = 0x50
  /// LR Register.
  | LR = 0x51
  /// Count Register.
  | CTR = 0x52
  /// FPSCR Register
  | FPSCR = 0x53

/// Shortcut for Register type.
type internal R = Register

/// This module exposes several useful functions to handle PPC32 registers.
[<RequireQualifiedAccess>]
module Register =
  let inline ofRegID (n: RegisterID): Register =
    int n |> LanguagePrimitives.EnumOfValue

  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  let ofString (str: string) =
    match str.ToLower () with
    | "r0" -> R.GPR0
    | "r1" -> R.GPR1
    | "r2" -> R.GPR2
    | "r3" -> R.GPR3
    | "r4" -> R.GPR4
    | "r5" -> R.GPR5
    | "r6" -> R.GPR6
    | "r7" -> R.GPR7
    | "r8" -> R.GPR8
    | "r9" -> R.GPR9
    | "r10" -> R.GPR10
    | "r11" -> R.GPR11
    | "r12" -> R.GPR12
    | "r13" -> R.GPR13
    | "r14" -> R.GPR14
    | "r15" -> R.GPR15
    | "r16" -> R.GPR16
    | "r17" -> R.GPR17
    | "r18" -> R.GPR18
    | "r19" -> R.GPR19
    | "r20" -> R.GPR20
    | "r21" -> R.GPR21
    | "r22" -> R.GPR22
    | "r23" -> R.GPR23
    | "r24" -> R.GPR24
    | "r25" -> R.GPR25
    | "r26" -> R.GPR26
    | "r27" -> R.GPR27
    | "r28" -> R.GPR28
    | "r29" -> R.GPR29
    | "r30" -> R.GPR30
    | "r31" -> R.GPR31
    | "f0" -> R.FPR0
    | "f1" -> R.FPR1
    | "f2" -> R.FPR2
    | "f3" -> R.FPR3
    | "f4" -> R.FPR4
    | "f5" -> R.FPR5
    | "f6" -> R.FPR6
    | "f7" -> R.FPR7
    | "f8" -> R.FPR8
    | "f9" -> R.FPR9
    | "f10" -> R.FPR10
    | "f11" -> R.FPR11
    | "f12" -> R.FPR12
    | "f13" -> R.FPR13
    | "f14" -> R.FPR14
    | "f15" -> R.FPR15
    | "f16" -> R.FPR16
    | "f17" -> R.FPR17
    | "f18" -> R.FPR18
    | "f19" -> R.FPR19
    | "f20" -> R.FPR20
    | "f21" -> R.FPR21
    | "f22" -> R.FPR22
    | "f23" -> R.FPR23
    | "f24" -> R.FPR24
    | "f25" -> R.FPR25
    | "f26" -> R.FPR26
    | "f27" -> R.FPR27
    | "f28" -> R.FPR28
    | "f29" -> R.FPR29
    | "f30" -> R.FPR30
    | "f31" -> R.FPR31
    | "cr0" -> R.CR0
    | "cr1" -> R.CR1
    | "cr2" -> R.CR2
    | "cr3" -> R.CR3
    | "cr4" -> R.CR4
    | "cr5" -> R.CR5
    | "cr6" -> R.CR6
    | "cr7" -> R.CR7
    | _ -> Utils.impossible ()

  let toString = function
    | R.GPR0 -> "r0"
    | R.GPR1 -> "r1"
    | R.GPR2 -> "r2"
    | R.GPR3 -> "r3"
    | R.GPR4 -> "r4"
    | R.GPR5 -> "r5"
    | R.GPR6 -> "r6"
    | R.GPR7 -> "r7"
    | R.GPR8 -> "r8"
    | R.GPR9 -> "r9"
    | R.GPR10 -> "r10"
    | R.GPR11 -> "r11"
    | R.GPR12 -> "r12"
    | R.GPR13 -> "r13"
    | R.GPR14 -> "r14"
    | R.GPR15 -> "r15"
    | R.GPR16 -> "r16"
    | R.GPR17 -> "r17"
    | R.GPR18 -> "r18"
    | R.GPR19 -> "r19"
    | R.GPR20 -> "r20"
    | R.GPR21 -> "r21"
    | R.GPR22 -> "r22"
    | R.GPR23 -> "r23"
    | R.GPR24 -> "r24"
    | R.GPR25 -> "r25"
    | R.GPR26 -> "r26"
    | R.GPR27 -> "r27"
    | R.GPR28 -> "r28"
    | R.GPR29 -> "r29"
    | R.GPR30 -> "r30"
    | R.GPR31 -> "r31"
    | R.FPR0 -> "f0"
    | R.FPR1 -> "f1"
    | R.FPR2 -> "f2"
    | R.FPR3 -> "f3"
    | R.FPR4 -> "f4"
    | R.FPR5 -> "f5"
    | R.FPR6 -> "f6"
    | R.FPR7 -> "f7"
    | R.FPR8 -> "f8"
    | R.FPR9 -> "f9"
    | R.FPR10 -> "f10"
    | R.FPR11 -> "f11"
    | R.FPR12 -> "f12"
    | R.FPR13 -> "f13"
    | R.FPR14 -> "f14"
    | R.FPR15 -> "f15"
    | R.FPR16 -> "f16"
    | R.FPR17 -> "f17"
    | R.FPR18 -> "f18"
    | R.FPR19 -> "f19"
    | R.FPR20 -> "f20"
    | R.FPR21 -> "f21"
    | R.FPR22 -> "f22"
    | R.FPR23 -> "f23"
    | R.FPR24 -> "f24"
    | R.FPR25 -> "f25"
    | R.FPR26 -> "f26"
    | R.FPR27 -> "f27"
    | R.FPR28 -> "f28"
    | R.FPR29 -> "f29"
    | R.FPR30 -> "f30"
    | R.FPR31 -> "f31"
    | R.CR0 -> "cr0"
    | R.CR1 -> "cr1"
    | R.CR2 -> "cr2"
    | R.CR3 -> "cr3"
    | R.CR4 -> "cr4"
    | R.CR5 -> "cr5"
    | R.CR6 -> "cr6"
    | R.CR7 -> "cr7"
    | _ -> Utils.impossible ()