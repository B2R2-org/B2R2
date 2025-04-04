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

/// Raised when there is an overlapping intervals from the interval tree.
exception RangeOverlapException

/// Raised when an AddrRange has the same Min and Max value, i.e., for invalid
/// interval.
exception InvalidAddrRangeException

/// This type represents a range of address values that are greater or equal to
/// the min value (inclusive) and are less than or equal to the max value
/// (inclusive).
type AddrRange =
  class
    /// <summary>
    /// Initialize an instance of AddrRange from a given interval.
    /// </summary>
    /// <param name="min">The start address.</param>
    /// <param name="max">The end address + 1.</param>
    /// <returns>
    /// An instance of AddrRange.
    /// </returns>
    new : min: Addr * max: Addr -> AddrRange

    /// <summary>
    /// Initialize an instance of AddrRange of size 1 has a single addr, i.e.,
    /// (addr - addr).
    /// </summary>
    /// <param name="addr">The start address.</param>
    /// <returns>
    /// An instance of AddrRange.
    /// </returns>
    new : addr: Addr -> AddrRange

    /// Minimum value (lower bound) of the interval.
    val Min: Addr

    /// Maximum value (upper bound) of the interval.
    val Max: Addr

    /// The number of addresses in this range.
    member Count: uint64

    /// <summary>
    /// Get the corresponding tuple (Addr, Addr) from the AddrRange.
    /// </summary>
    /// <returns>
    /// A tuple of min (inclusive) and max (exclusive).
    /// </returns>
    member ToTuple: unit -> Addr * Addr

    /// <summary>
    /// Slice the given AddrRange (target) based on my range, in such a way that
    /// the resulting range is always included in my range.
    /// </summary>
    /// <returns>
    /// </returns>
    member Slice: target: AddrRange -> AddrRange

    /// <summary>
    /// Check if the address range is including the given address.
    /// </summary>
    /// <returns>
    /// True if the address is included in the range. False otherwise.
    /// </returns>
    member inline IsIncluding: Addr -> bool

    /// <summary>
    /// Get the min value (inclusive) of the AddrRange.
    /// </summary>
    /// <returns>
    /// The min value.
    /// </returns>
    static member inline GetMin: AddrRange -> Addr

    /// <summary>
    /// Get the max value (exclusive) of the AddrRange.
    /// </summary>
    /// <returns>
    /// The max value.
    /// </returns>
    static member inline GetMax: AddrRange -> Addr
  end

// vim: set tw=80 sts=2 sw=2:
