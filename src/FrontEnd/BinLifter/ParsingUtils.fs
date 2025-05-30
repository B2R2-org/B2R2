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

/// Provides several utility functions to parse binary code.
module B2R2.FrontEnd.BinLifter.ParsingUtils

/// Provides several useful functions to access a 32-bit bit data represented as
/// either a uint32 or a uint64.
[<RequireQualifiedAccess>]
module Bits =
  /// Extract bit values located in between the given two offsets. The order of
  /// the offsets does not matter.
  let extract (binary: uint32) ofs1 ofs2 =
    let m, n = if max ofs1 ofs2 = ofs1 then ofs1, ofs2 else ofs2, ofs1
    let range = m - n + 1u
    if range > 31u then invalidOp "Invalid range of offsets given." else ()
    let mask = pown 2 (int range) - 1 |> uint32
    binary >>> int n &&& mask

  /// Pick a bit value at the given offset.
  let pick (binary: uint32) (pos: uint32) =
    binary >>> int pos &&& 0b1u

  /// Concatenate n1 and n2 by shifting n1 to the left by the given shift
  //amount.
  let concat (n1: uint32) (n2: uint32) shiftAmount =
    (n1 <<< shiftAmount) + n2

  /// Get a bit mask (in uint64) of the given size.
  let getBitMask64 size =
    assert (size <= 64)
    System.UInt64.MaxValue >>> (64 - size)

  /// Sign-extend the given bit vector `v` of the size `originalSize` to the
  /// target size `targetSize`.
  let signExtend originalSize targetSize (v: uint64) =
    assert (originalSize <= targetSize)
    if v >>> (originalSize - 1) = 0b0UL then v
    else (getBitMask64 targetSize - getBitMask64 originalSize) ||| v

