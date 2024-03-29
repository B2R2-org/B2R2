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

/// This exception is raised when an invalid WordSize is encountered.
exception InvalidWordSizeException

/// B2R2 represents the word size of a CPU with WordSize.
type WordSize =
  | Bit8 = 8
  | Bit16 = 16
  | Bit32 = 32
  | Bit64 = 64
  | Bit128 = 128
  | Bit256 = 256

/// A helper module for the WordSize type.
[<RequireQualifiedAccess>]
module WordSize =
  /// Transform a string into a word size.
  [<CompiledName "OfString">]
  let ofString = function
    | "8"  -> WordSize.Bit8
    | "16"  -> WordSize.Bit16
    | "32"  -> WordSize.Bit32
    | "64"  -> WordSize.Bit64
    | "128" -> WordSize.Bit128
    | "256" -> WordSize.Bit256
    | _ -> raise InvalidWordSizeException

  /// Transform a word size into a byte length.
  [<CompiledName "ToByteWidth">]
  let toByteWidth (wordSize: WordSize) = int32 wordSize / 8

  /// Transform a word size into a RegType.
  [<CompiledName "ToRegType">]
  let toRegType = function
    | WordSize.Bit8 -> 8<rt>
    | WordSize.Bit16 -> 16<rt>
    | WordSize.Bit32  -> 32<rt>
    | WordSize.Bit64  -> 64<rt>
    | WordSize.Bit128 -> 128<rt>
    | WordSize.Bit256 -> 256<rt>
    | _ -> raise InvalidWordSizeException

  /// Transform a word size into a string.
  [<CompiledName "ToString">]
  let toString wordSz = (toRegType wordSz).ToString ()

  /// Is the given word size 32 bit?
  [<CompiledName "Is32">]
  let is32 wordSz = wordSz = WordSize.Bit32

  /// Is the given word size 64 bit?
  [<CompiledName "Is64">]
  let is64 wordSz = wordSz = WordSize.Bit64

  /// Is the given word size 128 bit?
  [<CompiledName "Is128">]
  let is128 wordSz = wordSz = WordSize.Bit128

  /// Is the given word size 256 bit?
  [<CompiledName "Is256">]
  let is256 wordSz = wordSz = WordSize.Bit256