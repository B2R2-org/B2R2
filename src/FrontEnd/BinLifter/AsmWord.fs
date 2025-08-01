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

namespace B2R2.FrontEnd.BinLifter

/// Represents a smallest chunk of an assembly statement. Specifically, we
/// divide an assembly statement into a series of AsmWords, each of which
/// represents a chunk of the assembly statement. For example, the assembly
/// statement "mov eax, 1" can be divided into five AsmWords: "mov", " ", "eax",
/// ", ", and "1". The first AsmWord is a mnemonic, the second is a space
/// character, the third is a variable (register), the fourth is a space
/// character, and the fifth is a value (immediate).
type AsmWord =
  { /// The kind of the assembly word.
    AsmWordKind: AsmWordKind
    /// The string value of the assembly word.
    AsmWordValue: string }
with
  /// Returns the length of the assembly word.
  static member Width { AsmWordValue = s } = s.Length

  /// Returns the string value of the assembly word.
  static member ToString { AsmWordValue = s } = s

  /// Returns a tuple of the assembly word value and its kind as a string.
  static member ToStringTuple { AsmWordKind = k; AsmWordValue = s } =
    match k with
    | AsmWordKind.Address -> s, "address"
    | AsmWordKind.Mnemonic -> s, "mnemonic"
    | AsmWordKind.Variable -> s, "variable"
    | AsmWordKind.Value -> s, "value"
    | AsmWordKind.String -> s, "string"
    | _ -> failwith "Impossible"

/// Represents a kind of a assembly word.
and AsmWordKind =
  /// An address of the given instruction.
  | Address = 1
  /// An opcode.
  | Mnemonic = 2
  /// An variable (such as a register).
  | Variable = 3
  /// A value (such as an immediate).
  | Value = 4
  /// A simple string that can be ignored.
  | String = 0

