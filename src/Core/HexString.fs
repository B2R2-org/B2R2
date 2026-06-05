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

/// Provides helper functions to construct hexadecimal strings from integers.
/// Each string is prefixed with "0x", lowercase, and not zero-padded. Signed
/// values are formatted as their two's complement bit pattern.
[<RequireQualifiedAccess>]
module HexString =
  /// <summary>
  /// Converts an int16 value to a hex string (e.g., <c>0xffff</c> for -1).
  /// </summary>
  [<CompiledName "OfInt16">]
  let inline ofInt16 (v: int16) = $"0x{uint16 v:x}"

  /// Converts a uint16 value to a hex string.
  [<CompiledName "OfUInt16">]
  let inline ofUInt16 (v: uint16) = $"0x{v:x}"

  /// <summary>
  /// Converts an int32 value to a hex string (e.g., <c>0xffffffff</c> for -1).
  /// </summary>
  [<CompiledName "OfInt32">]
  let inline ofInt32 (v: int) = $"0x{uint32 v:x}"

  /// Converts a uint32 value to a hex string.
  [<CompiledName "OfUInt32">]
  let inline ofUInt32 (v: uint32) = $"0x{v:x}"

  /// <summary>
  /// Converts an int64 value to a hex string (e.g.,
  /// <c>0xffffffffffffffff</c> for -1).
  /// </summary>
  [<CompiledName "OfInt64">]
  let inline ofInt64 (v: int64) = $"0x{uint64 v:x}"

  /// Converts a uint64 value to a hex string.
  [<CompiledName "OfUInt64">]
  let inline ofUInt64 (v: uint64) = $"0x{v:x}"
