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
    | "R0" -> R.R0 (* FIXME: Add Registers *)
    | "R1" -> R.R1
    | "R2" -> R.R2
    | "R3" -> R.R3
    | "R4" -> R.R4
    | "R5" -> R.R5
    | "R6" -> R.R6
    | "R7" -> R.R7
    | "R8" -> R.R8
    | "R9" -> R.R9
    | "R10" -> R.R10
    | "R11" -> R.R11
    | "R12" -> R.R12
    | "R13" -> R.R13
    | "R14" -> R.R14
    | "R15" -> R.R15
    | "R16" -> R.R16
    | "R17" -> R.R17
    | "R18" -> R.R18
    | "R19" -> R.R19
    | "R20" -> R.R20
    | "R21" -> R.R21
    | "R22" -> R.R22
    | "R23" -> R.R23
    | "R24" -> R.R24
    | "R25" -> R.R25
    | "R26" -> R.R26
    | "R27" -> R.R27
    | "R28" -> R.R28
    | "R29" -> R.R29
    | "R30" -> R.R30
    | "R31" -> R.R31
    | "F0" -> F.F0
    | "F1" -> F.F1
    | "F2" -> F.F2
    | "F3" -> F.F3
    | "F4" -> F.F4
    | "F5" -> F.F5
    | "F6" -> F.F6
    | "F7" -> F.F7
    | "F8" -> F.F8
    | "F9" -> F.F9
    | "F10" -> F.F10
    | "F11" -> F.F11
    | "F12" -> F.F12
    | "F13" -> F.F13
    | "F14" -> F.F14
    | "F15" -> F.F15
    | "F16" -> F.F16
    | "F17" -> F.F17
    | "F18" -> F.F18
    | "F19" -> F.F19
    | "F20" -> F.F20
    | "F21" -> F.F21
    | "F22" -> F.F22
    | "F23" -> F.F23
    | "F24" -> F.F24
    | "F25" -> F.F25
    | "F26" -> F.F26
    | "F27" -> F.F27
    | "F28" -> F.F28
    | "F29" -> F.F29
    | "F30" -> F.F30
    | "F31" -> F.F31
    | "CR0" -> CR.CR0
    | "CR1" -> CR.CR1
    | "CR2" -> CR.CR2
    | "CR3" -> CR.CR3
    | "CR4" -> CR.CR4
    | "CR5" -> CR.CR5
    | "CR6" -> CR.CR6
    | "CR7" -> CR.CR7
    | _ -> Utils.impossible ()

  let toString = function
    | R.R0 -> "R0" (* FIXME: Add Registers *)
    | R.R1 -> "R1"
    | R.R2 -> "R2"
    | R.R3 -> "R3"
    | R.R4 -> "R4"
    | R.R5 -> "R5"
    | R.R6 -> "R6"
    | R.R7 -> "R7"
    | R.R8 -> "R8"
    | R.R9 -> "R9"
    | R.R10 -> "R10"
    | R.R11 -> "R11"
    | R.R12 -> "R12"
    | R.R13 -> "R13"
    | R.R14 -> "R14"
    | R.R15 -> "R15"
    | R.R16 -> "R16"
    | R.R17 -> "R17"
    | R.R18 -> "R18"
    | R.R19 -> "R19"
    | R.R20 -> "R20"
    | R.R21 -> "R21"
    | R.R22 -> "R22"
    | R.R23 -> "R23"
    | R.R24 -> "R24"
    | R.R25 -> "R25"
    | R.R26 -> "R26"
    | R.R27 -> "R27"
    | R.R28 -> "R28"
    | R.R29 -> "R29"
    | R.R30 -> "R30"
    | R.R31 -> "R31"
    | F.F0 -> "F0"
    | F.F1 -> "F1"
    | F.F2 -> "F2"
    | F.F3 -> "F3"
    | F.F4 -> "F4"
    | F.F5 -> "F5"
    | F.F6 -> "F6"
    | F.F7 -> "F7"
    | F.F8 -> "F8"
    | F.F9 -> "F9"
    | F.F10 -> "F10"
    | F.F11 -> "F11"
    | F.F12 -> "F12"
    | F.F13 -> "F13"
    | F.F14 -> "F14"
    | F.F15 -> "F15"
    | F.F16 -> "F16"
    | F.F17 -> "F17"
    | F.F18 -> "F18"
    | F.F19 -> "F19"
    | F.F20 -> "F20"
    | F.F21 -> "F21"
    | F.F22 -> "F22"
    | F.F23 -> "F23"
    | F.F24 -> "F24"
    | F.F25 -> "F25"
    | F.F26 -> "F26"
    | F.F27 -> "F27"
    | F.F28 -> "F28"
    | F.F29 -> "F29"
    | F.F30 -> "F30"
    | F.F31 -> "F31"
    | CR.CR0 -> "CR0"
    | CR.CR1 -> "CR1"
    | CR.CR2 -> "CR2"
    | CR.CR3 -> "CR3"
    | CR.CR4 -> "CR4"
    | CR.CR5 -> "CR5"
    | CR.CR6 -> "CR6"
    | CR.CR7 -> "CR7"
    | _ -> Utils.impossible ()