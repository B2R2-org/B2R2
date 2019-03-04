(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

/// It is sometimes convenient to consider a binary chunk as a byte array. This
/// module provides several useful functions to deal with byte arrays.
module B2R2.ByteArray

/// Convert a hex string to a byte array.
val ofHexString : string -> byte []

/// Extract a C-string (string that ends with a NULL char) from a byte array.
val extractCString : byte [] -> int -> string

/// Find and return the offsets of all the matching byte positions. The search
/// starts from the offset.
val findIdxs : offset: uint64 -> pattern: byte [] -> buf: byte [] -> uint64 list

/// Find a matching byte position. If there is no match, this function will
/// return None.
val tryFindIdx : uint64 -> byte [] -> byte [] -> uint64 option

/// Convert a byte array into a uint32 array.
val toUInt32Arr : byte [] -> uint32 []
