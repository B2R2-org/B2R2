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

namespace B2R2.FrontEnd

open System.Collections

/// A kind of a term within an assembly statement.
type AsmWordKind =
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

/// We divide an assembly statement into a series of AsmWord, which represents a
/// word (string) in the statement.
type AsmWord = {
  AsmWordKind: AsmWordKind
  AsmWordValue: string
}
with
  static member Width { AsmWordValue = s } = s.Length
  static member ToString { AsmWordValue = s } = s
  static member ToStringTuple { AsmWordKind = k; AsmWordValue = s } =
    match k with
    | AsmWordKind.Address -> s, "address"
    | AsmWordKind.Mnemonic -> s, "mnemonic"
    | AsmWordKind.Variable -> s, "variable"
    | AsmWordKind.Value -> s, "value"
    | AsmWordKind.String -> s, "string"
    | _ -> failwith "Impossible"

/// Builder for an array of AsmWords.
type AsmWordBuilder =
  inherit Generic.List<AsmWord>

  /// <summary>
  ///   Initialize an IR statement builder of internal buffer size n.
  /// </summary>
  /// <param name="n">The size of the internal buffer.</param>
  new (n: int) = { inherit Generic.List<AsmWord>(n) }

  /// <summary>
  ///   Append a new AsmWord to the builder.
  /// </summary>
  /// <param name="stmt">AsmWord to add.</param>
  member __.Append stmt = __.Add (stmt); __

  /// <summary>
  ///   Create an array of AsmWords from the buffer.
  /// </summary>
  /// <returns>
  ///   Returns an array of AsmWords.
  /// </returns>
  member __.Finish () = __.ToArray ()
