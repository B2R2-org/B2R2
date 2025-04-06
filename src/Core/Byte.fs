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
/// Provides functions for handling a <c>byte</c> value. See also: <seealso
/// cref="M:System.Byte"/>
/// </summary>
[<RequireQualifiedAccess>]
module B2R2.Byte

/// Check if a byte is null.
[<CompiledName "IsNull">]
let isNull b = b = 0uy

/// Check if a byte is printable.
[<CompiledName "IsPrintable">]
let isPrintable b = b >= 33uy && b <= 126uy

/// Check if a byte is a whitespace.
[<CompiledName "IsWhitespace">]
let isWhitespace b = b = 32uy || (b >= 9uy && b <= 13uy)

/// Check if a byte is a control character.
[<CompiledName "IsControl">]
let isControl b =
  b = 127uy || (b >= 1uy && b <= 8uy) || (b >= 14uy && b <= 31uy)

/// Get a string representation of a byte used in B2R2. A null byte is
/// represented as a dot, a printable byte is represented as an ASCII
/// character, a whitespace is represented as an underscore, and a control
/// character is represented as an asterisk.
[<CompiledName "GetRepresentation">]
let getRepresentation (b: byte) =
  if isNull b then "."
  elif isPrintable b then (char b).ToString ()
  elif isWhitespace b then "_"
  elif isControl b then "*"
  else "."
