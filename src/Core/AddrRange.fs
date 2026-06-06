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

/// Raised when there are overlapping intervals from the interval tree.
exception RangeOverlapException

/// Raised when an invalid AddrRange is constructed, i.e., when the min address
/// is greater than the max address.
exception InvalidAddrRangeException

/// <summary>
/// Represents a range of address values that are greater than or equal to the
/// <c>Min</c> value (inclusive) and are less than or equal to the <c>Max</c>
/// value (inclusive).
/// </summary>
type AddrRange =
  { /// The minimum value (lower bound) of the interval.
    Min: Addr
    /// The maximum value (upper bound) of the interval.
    Max: Addr }
with
  /// <summary>
  /// Gets the number of addresses in this range.
  /// </summary>
  member this.Count with get() = this.Max - this.Min + 1UL

  /// <summary>
  /// Gets the corresponding tuple (Addr, Addr) from the AddrRange.
  /// </summary>
  /// <returns>
  /// A tuple of min (inclusive) and max (inclusive).
  /// </returns>
  member this.ToTuple() = this.Min, this.Max

  /// <summary>
  /// Slices the given AddrRange (target) based on this range, in such a way
  /// that the resulting range is always included in this range.
  /// </summary>
  /// <param name="target">The AddrRange to slice.</param>
  /// <returns>
  /// The sliced AddrRange.
  /// </returns>
  member this.Slice(target: AddrRange) =
    let l = max this.Min target.Min
    let h = min this.Max target.Max
    assert (l <= h)
    { Min = l; Max = h }

  /// <summary>
  /// Checks if the address range includes the given address.
  /// </summary>
  /// <param name="addr">The address to check.</param>
  /// <returns>
  /// <c>true</c> if the address is included in the range; otherwise
  /// <c>false</c>.
  /// </returns>
  member inline this.IsIncluding(addr: Addr) =
    this.Min <= addr && addr <= this.Max

  override this.ToString() = $"{this.Min:x} -- {this.Max:x}"


/// <summary>
/// Provides a useful set of functions for handling <see
/// cref='T:B2R2.AddrRange'/> values.
/// </summary>
[<RequireQualifiedAccess>]
module AddrRange =

  /// <summary>
  /// Creates an <see cref='T:B2R2.AddrRange'/> from the given min and max
  /// addresses. Raises <see cref='T:B2R2.InvalidAddrRangeException'/> if min
  /// is greater than max.
  /// </summary>
  /// <param name="min">The start address (inclusive).</param>
  /// <param name="max">The end address (inclusive).</param>
  /// <returns>
  /// An <see cref='T:B2R2.AddrRange'/> with Min = <paramref name="min"/> and
  /// Max = <paramref name="max"/>.
  /// </returns>
  [<CompiledName "Create">]
  let create min max =
    if min > max then raise InvalidAddrRangeException else ()
    { Min = min; Max = max }

  /// <summary>
  /// Creates an <see cref='T:B2R2.AddrRange'/> of size 1 containing only the
  /// given address, i.e., Min = Max = <paramref name="addr"/>.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <returns>
  /// An <see cref='T:B2R2.AddrRange'/> where Min and Max are both
  /// <paramref name="addr"/>.
  /// </returns>
  [<CompiledName "Singleton">]
  let singleton addr =
    { Min = addr; Max = addr }
