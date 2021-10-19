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

/// Shortcut for Register type.
type internal R = Register

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
    | _ -> Utils.impossible ()

