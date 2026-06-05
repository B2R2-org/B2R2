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

/// <summary>
/// Provides useful functions for handling <c>string</c> values.
/// </summary>
[<RequireQualifiedAccess>]
module B2R2.String

/// Encodes a string to a UTF-8 byte array.
[<CompiledName "ToUtf8Bytes">]
let toUtf8Bytes (str: string) =
  System.Text.Encoding.UTF8.GetBytes str

/// Decodes a UTF-8 byte array to a string.
[<CompiledName "FromUtf8Bytes">]
let fromUtf8Bytes (bs: byte[]) =
  System.Text.Encoding.UTF8.GetString bs

/// Encodes a string to an ASCII byte array. Throws an exception if the string
/// contains non-ASCII characters.
[<CompiledName "ToAsciiBytes">]
let toAsciiBytes (str: string) =
  if str |> Seq.exists (fun c -> int c > 127) then
    invalidArg (nameof str) "String contains non-ASCII characters."
  else
    System.Text.Encoding.ASCII.GetBytes str

/// Decodes an ASCII byte array to a string. Bytes outside the ASCII range
/// (0–127) are replaced with '?'.
[<CompiledName "FromAsciiBytes">]
let fromAsciiBytes (bs: byte[]) =
  System.Text.Encoding.ASCII.GetString bs

/// Wraps a string with a pair of parentheses.
[<CompiledName "WrapParen">]
let wrapParen s =
  "(" + s + ")"

/// Wraps a string with a pair of square brackets.
[<CompiledName "WrapSquareBracket">]
let wrapSquareBracket s =
  "[" + s + "]"

/// Wraps a string with a pair of angle brackets.
[<CompiledName "WrapAngleBracket">]
let wrapAngleBracket s =
  "<" + s + ">"
