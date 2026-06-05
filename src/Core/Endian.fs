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
  /// Little endian.
  | Little = 1
  /// Big endian.
  | Big = 2

/// Provides functions to work with Endian.
[<RequireQualifiedAccess>]
module Endian =
  /// <summary>
  /// Gets an <see cref='T:B2R2.Endian'/> value from a string. Accepts "l",
  /// "le", or "little" for little endian, and "b", "be", or "big" for big
  /// endian (case-insensitive). Raises <see
  /// cref='T:B2R2.InvalidEndianException'/> if the string is not recognized.
  /// </summary>
  /// <param name="str">A string representing endianness.</param>
  /// <returns>
  /// An <see cref='T:B2R2.Endian'/> value corresponding to
  /// <paramref name="str"/>.
  /// </returns>
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant() with
    | "l" | "le" | "little" -> Endian.Little
    | "b" | "be" | "big" -> Endian.Big
    | _ -> raise InvalidEndianException

  /// <summary>
  /// Gets the string representation of an <see cref='T:B2R2.Endian'/> value.
  /// Raises <see cref='T:B2R2.InvalidEndianException'/> for invalid values.
  /// </summary>
  /// <param name="endian">The Endian value to convert.</param>
  /// <returns>
  /// "Little Endian" or "Big Endian".
  /// </returns>
  [<CompiledName "ToString">]
  let toString (endian: Endian) =
    match endian with
    | Endian.Little -> "Little Endian"
    | Endian.Big -> "Big Endian"
    | _ -> raise InvalidEndianException
