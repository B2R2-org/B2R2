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

/// AddrRange is a tuple (min, max) that represents a range of address values
/// that are greater or equal to the min value (inclusive) and are less than the
/// max value (exclusive). To access the min and the max value of a range, use
/// either getMin or getMax function.
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

    /// Minimum value (lower bound) of the interval.
    val Min: Addr

    /// Maximum value (upper bound) of the interval.
    val Max: Addr

    /// <summary>
    /// Get the corresponding tuple (Addr, Addr) from the AddrRange.
    /// </summary>
    /// <returns>
    /// A tuple of min (inclusive) and max (exclusive).
    /// </returns>
    member ToTuple: unit -> Addr * Addr

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
