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

namespace B2R2.FrontEnd.BinLifter.AVR

open B2R2

type Register =
  | R0 = 0x0 (* TODO *)
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
  | X = 0x20
  | Y = 0x21
  | Z = 0x22
  | IF = 0x23
  | TF = 0x24
  | HF = 0x25
  | SF = 0x26
  | VF = 0x27
  | NF = 0x28
  | ZF = 0x29
  | CF = 0x2A
  | PC = 0x2B
  | SP = 0x2C

/// Shortcut for Register type.
type internal R = Register

/// This module exposes several useful functions to handle AVR registers.
[<RequireQualifiedAccess>]
module Register =
  let inline ofRegID (n: RegisterID): Register =
    int n |> LanguagePrimitives.EnumOfValue

  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  let ofString (str: string) =
    match str.ToLower () with
    | "r1" -> R.R0 (* TODO *)
    | "r2" -> R.R1
    | "r3" -> R.R2
    | "r4" -> R.R3
    | "r5" -> R.R4
    | "r6" -> R.R5
    | "r7" -> R.R6
    | "r8" -> R.R7
    | "r9" -> R.R8
    | "r10" -> R.R9
    | "r11" -> R.R10
    | "r12" -> R.R11
    | "r13" -> R.R12
    | "r14" -> R.R13
    | "r15" -> R.R14
    | "r16" -> R.R15
    | "r17" -> R.R16
    | "r18" -> R.R17
    | "r19" -> R.R18
    | "r20" -> R.R19
    | "r21" -> R.R20
    | "r22" -> R.R21
    | "r23" -> R.R22
    | "r24" -> R.R23
    | "r25" -> R.R24
    | "r26" -> R.R25
    | "r27" -> R.R26
    | "r28" -> R.R27
    | "r29" -> R.R28
    | "r30" -> R.R29
    | "r31" -> R.R30
    | "r32" -> R.R31
    | "IF" -> R.IF
    | "TF" -> R.TF
    | "HF" -> R.HF
    | "SF" -> R.SF
    | "VF" -> R.VF
    | "NF" -> R.NF
    | "ZF" -> R.ZF
    | "CF" -> R.CF
    | "PC" -> R.PC
    | "SP" -> R.SP
    | _ -> Utils.impossible ()

  let toString = function
    | R.R0 -> "r0" (* TODO *)
    | R.R1 -> "r1"
    | R.R2 -> "r2"
    | R.R3 -> "r3"
    | R.R4 -> "r4"
    | R.R5  -> "r5"
    | R.R6 -> "r6"
    | R.R7 -> "r7"
    | R.R8 -> "r8"
    | R.R9 -> "r9"
    | R.R10 -> "r10"
    | R.R11 -> "r11"
    | R.R12  -> "r12"
    | R.R13 -> "r13"
    | R.R14 -> "r14"
    | R.R15 -> "r15"
    | R.R16  -> "r16"
    | R.R17 -> "r17"
    | R.R18 -> "r18"
    | R.R19 -> "r19"
    | R.R20  -> "r20"
    | R.R21 -> "r21"
    | R.R22 -> "r22"
    | R.R23 -> "r23"
    | R.R24 -> "r24"
    | R.R25  -> "r25"
    | R.R26 -> "r26"
    | R.R27 -> "r27"
    | R.R28 -> "r28"
    | R.R29  -> "r29"
    | R.R30 -> "r30"
    | R.R31 -> "r31"
    | R.X -> "X"
    | R.Y -> "Y"
    | R.Z -> "Z"
    | R.PC -> "pc"
    | R.SP -> "sp"
    | _ -> Utils.impossible ()

