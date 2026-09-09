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

namespace B2R2.FrontEnd.BPF

open B2R2

/// <namespacedoc>
///   <summary>
///   Contains types and functions for working with the eBPF instructions.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents registers for eBPF. The machine keeps eleven of them and no
/// more: ten a program computes with and one holding where its stack frame
/// begins, which a program reads and never writes. Each is a quadword wide,
/// and an instruction of the thirty-two bit class reads the lower half of one
/// and clears the upper half when it writes.
/// </summary>
type Register =
  /// Where a helper leaves what it returns, and where a program leaves what it
  /// returns to whatever called it.
  | R0 = 0x0
  /// The first of the five registers an argument is passed in.
  | R1 = 0x1
  | R2 = 0x2
  | R3 = 0x3
  | R4 = 0x4
  /// The last of the five registers an argument is passed in.
  | R5 = 0x5
  /// The first of the registers a called function leaves as it found.
  | R6 = 0x6
  | R7 = 0x7
  | R8 = 0x8
  /// The last of the registers a called function leaves as it found.
  | R9 = 0x9
  /// Where this program's stack frame begins, which is read-only.
  | R10 = 0xA
  /// The program counter, which no instruction names and which counts bytes
  /// rather than the instructions the encoding counts.
  | PC = 0xB

/// Provides functions to handle eBPF registers.
[<RequireQualifiedAccess>]
module Register =
  /// Returns the eBPF register from a register ID.
  [<CompiledName "OfRegID">]
  let inline ofRegID (rid: RegisterID): Register =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Returns the eBPF register from a string representation.
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
    | "r10" | "fp" -> Register.R10
    | "pc" -> Register.PC
    | _ -> Terminator.impossible ()

  /// Returns the register ID of an eBPF register.
  [<CompiledName "ToRegID">]
  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue(reg) |> RegisterID.create

  /// Returns the string representation of an eBPF register.
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
    | Register.PC -> "pc"
    | _ -> Terminator.impossible ()

  /// Returns the register type (bit width) of an eBPF register, which is a
  /// quadword for every one of them.
  [<CompiledName "ToRegType">]
  let toRegType (_reg: Register) = 64<rt>

// vim: set tw=80 sts=2 sw=2:
