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

/// Provides useful functions for handling <c>string</c> values.
[<RequireQualifiedAccess>]
module B2R2.String

/// Converts a string to a byte array.
[<CompiledName "ToBytes">]
let toBytes (str: string) = str.ToCharArray () |> Array.map byte

/// Converts a byte array to a string.
[<CompiledName "FromBytes">]
let fromBytes (bs: byte []) = Array.map char bs |> System.String

/// Wraps a string with a pair of parentheses.
[<CompiledName "WrapParen">]
let wrapParen s =
  "(" + s + ")"

/// Wraps a string with a pair of square brackets.
[<CompiledName "WrapSqrdBracket">]
let wrapSqrdBracket s =
  "[" + s + "]"

/// Wraps a string with a pair of curly brackets.
[<CompiledName "WrapCurlyBracket">]
let wrapAngleBracket s =
  "<" + s + ">"
