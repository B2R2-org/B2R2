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

namespace B2R2

/// Raised when an invalid Endian value is used.
exception InvalidEndianException

/// Represents the endianness used in a binary.
type Endian =
  /// Little endian
  | Little = 1
  /// Big endian
  | Big = 2

/// Provides functions to work with Endian.
[<RequireQualifiedAccess>]
module Endian =
  /// <summary>
  /// Get Endian from a string.
  /// </summary>
  /// <param name="str">The given string.</param>
  /// <returns>
  /// Endian.
  /// </returns>
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant () with
    | "l" | "le" | "little" -> Endian.Little
    | "b" | "be" | "big" -> Endian.Big
    | _     -> failwith "Wrong endian specified."

  /// <summary>
  /// Get the string representation from an Endian.
  /// </summary>
  [<CompiledName "ToString">]
  let toString = function
    | Endian.Little -> "Little Endian"
    | Endian.Big -> "Big Endian"
    | _ -> raise InvalidEndianException
