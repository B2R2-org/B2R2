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

/// Raised when an invalid WordSize is encountered.
exception InvalidWordSizeException

/// <summary>
/// Represents the word size of a CPU. The word size is the number of bits that
/// the CPU can naturally process in a single operation.
/// </summary>
type WordSize =
  /// 8-bit word size.
  | Bit8 = 8
  /// 16-bit word size.
  | Bit16 = 16
  /// 32-bit word size.
  | Bit32 = 32
  /// 64-bit word size.
  | Bit64 = 64
  /// 128-bit word size.
  | Bit128 = 128
  /// 256-bit word size.
  | Bit256 = 256

/// <summary>
/// Provides helper functions for handling the <see cref='T:B2R2.WordSize'/>
/// type.
/// </summary>
[<RequireQualifiedAccess>]
module WordSize =
  /// <summary>
  /// Transforms a <c>string</c> into a word size (<see
  /// cref='T:B2R2.WordSize'/>).
  /// </summary>
  [<CompiledName "OfString">]
  let ofString = function
    | "8"  -> WordSize.Bit8
    | "16"  -> WordSize.Bit16
    | "32"  -> WordSize.Bit32
    | "64"  -> WordSize.Bit64
    | "128" -> WordSize.Bit128
    | "256" -> WordSize.Bit256
    | _ -> raise InvalidWordSizeException

  /// <summary>
  /// Transforms a word size (<see cref='T:B2R2.WordSize'/>) into a byte length.
  /// </summary>
  [<CompiledName "ToByteWidth">]
  let toByteWidth (wordSize: WordSize) = int32 wordSize / 8

  /// <summary>
  /// Transforms a word size (<see cref='T:B2R2.WordSize'/>) into a RegType.
  /// </summary>
  [<CompiledName "ToRegType">]
  let toRegType = function
    | WordSize.Bit8 -> 8<rt>
    | WordSize.Bit16 -> 16<rt>
    | WordSize.Bit32  -> 32<rt>
    | WordSize.Bit64  -> 64<rt>
    | WordSize.Bit128 -> 128<rt>
    | WordSize.Bit256 -> 256<rt>
    | _ -> raise InvalidWordSizeException

  /// <summary>
  /// Transforms a word size (<see cref='T:B2R2.WordSize'/>) into a
  /// <c>string</c>.
  /// </summary>
  [<CompiledName "ToString">]
  let toString wordSz = (toRegType wordSz).ToString ()

  /// Checks if the given word size is 32 bit.
  [<CompiledName "Is32">]
  let is32 wordSz = wordSz = WordSize.Bit32

  /// Checks if the given word size is 64 bit.
  [<CompiledName "Is64">]
  let is64 wordSz = wordSz = WordSize.Bit64

  /// Checks if the given word size is 128 bit.
  [<CompiledName "Is128">]
  let is128 wordSz = wordSz = WordSize.Bit128

  /// Checks if the given word size is 256 bit.
  [<CompiledName "Is256">]
  let is256 wordSz = wordSz = WordSize.Bit256