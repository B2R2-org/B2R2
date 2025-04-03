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

namespace B2R2.FrontEnd.AVR

open B2R2

/// <summary>
/// Registers for AVR.<para/>
/// </summary>
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

/// Helper module for AVR registers.
[<RequireQualifiedAccess>]
module Register =
  /// Get the AVR register from a register ID.
  [<CompiledName "OfRegID">]
  let inline ofRegID (rid: RegisterID): Register =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Get the AVR register from a string representation.
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant () with
    | "r1" -> Register.R0
    | "r2" -> Register.R1
    | "r3" -> Register.R2
    | "r4" -> Register.R3
    | "r5" -> Register.R4
    | "r6" -> Register.R5
    | "r7" -> Register.R6
    | "r8" -> Register.R7
    | "r9" -> Register.R8
    | "r10" -> Register.R9
    | "r11" -> Register.R10
    | "r12" -> Register.R11
    | "r13" -> Register.R12
    | "r14" -> Register.R13
    | "r15" -> Register.R14
    | "r16" -> Register.R15
    | "r17" -> Register.R16
    | "r18" -> Register.R17
    | "r19" -> Register.R18
    | "r20" -> Register.R19
    | "r21" -> Register.R20
    | "r22" -> Register.R21
    | "r23" -> Register.R22
    | "r24" -> Register.R23
    | "r25" -> Register.R24
    | "r26" -> Register.R25
    | "r27" -> Register.R26
    | "r28" -> Register.R27
    | "r29" -> Register.R28
    | "r30" -> Register.R29
    | "r31" -> Register.R30
    | "r32" -> Register.R31
    | "IF" -> Register.IF
    | "TF" -> Register.TF
    | "HF" -> Register.HF
    | "SF" -> Register.SF
    | "VF" -> Register.VF
    | "NF" -> Register.NF
    | "ZF" -> Register.ZF
    | "CF" -> Register.CF
    | "PC" -> Register.PC
    | "SP" -> Register.SP
    | _ -> Terminator.impossible ()

  /// Get the register ID of an AVR register.
  [<CompiledName "ToRegID">]
  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  /// Get the string representation of an AVR register.
  [<CompiledName "ToString">]
  let toString reg =
    match reg with
    | Register.R0 -> "r0"
    | Register.R1 -> "r1"
    | Register.R2 -> "r2"
    | Register.R3 -> "r3"
    | Register.R4 -> "r4"
    | Register.R5  -> "r5"
    | Register.R6 -> "r6"
    | Register.R7 -> "r7"
    | Register.R8 -> "r8"
    | Register.R9 -> "r9"
    | Register.R10 -> "r10"
    | Register.R11 -> "r11"
    | Register.R12  -> "r12"
    | Register.R13 -> "r13"
    | Register.R14 -> "r14"
    | Register.R15 -> "r15"
    | Register.R16  -> "r16"
    | Register.R17 -> "r17"
    | Register.R18 -> "r18"
    | Register.R19 -> "r19"
    | Register.R20  -> "r20"
    | Register.R21 -> "r21"
    | Register.R22 -> "r22"
    | Register.R23 -> "r23"
    | Register.R24 -> "r24"
    | Register.R25  -> "r25"
    | Register.R26 -> "r26"
    | Register.R27 -> "r27"
    | Register.R28 -> "r28"
    | Register.R29  -> "r29"
    | Register.R30 -> "r30"
    | Register.R31 -> "r31"
    | Register.X -> "X"
    | Register.Y -> "Y"
    | Register.Z -> "Z"
    | Register.PC -> "pc"
    | Register.SP -> "sp"
    | _ -> Terminator.impossible ()
